// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 PolitCubes
//
// An in-game benchmark for the real client (Forge 1.7.10): run the same client without the guard
// and through it, read the numbers this mod leaves behind (tests/perf/minecraft/run.py does all
// of that). No keyboard or mouse is needed — synthetic input would be dropped by the guard, so the
// mod drives everything itself:
//   1. waits for the main menu, notes how long the client took to get there;
//   2. opens a single-player world (-Dmcbench.world, default "New World");
//   3. warms up (chunks load, the JIT settles), then for the measured window turns the camera a
//      full circle every 6 s (by game ticks, so every run sees the same scenery) and records the
//      time of every rendered frame;
//   4. writes mebet-bench-result.json in the game folder and closes the client.
// Minecraft is reached by reflection and found by types where it can be (GuiScreen, WorldClient),
// so the mod does not depend on obfuscated names more than it has to.

package mebet.bench;

import cpw.mods.fml.common.FMLCommonHandler;
import cpw.mods.fml.common.Mod;
import cpw.mods.fml.common.event.FMLInitializationEvent;
import cpw.mods.fml.common.eventhandler.SubscribeEvent;
import cpw.mods.fml.common.gameevent.TickEvent;

import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

@Mod(modid = "mebetbench", name = "Mebet bench", version = "1", acceptableRemoteVersions = "*")
public class MebetBenchMod {
    private static final String WORLD = System.getProperty("mcbench.world", "New World");
    private static final double WARMUP_S = Double.parseDouble(System.getProperty("mcbench.warmup", "20"));
    private static final double MEASURE_S = Double.parseDouble(System.getProperty("mcbench.measure", "60"));

    private enum State { MENU, LOADING, WARMUP, MEASURE, DONE }

    private State state = State.MENU;
    private long stateSince = System.nanoTime(), firstTick;
    private long menuMs, worldMs;
    private long[] frames = new long[1 << 20];
    private int n;
    private long lastFrame;

    private Object mc;
    private Field currentScreen, theWorld, thePlayer, yaw, prevYaw;
    private Method launchWorld, shutdown;

    @Mod.EventHandler
    public void init(FMLInitializationEvent e) {
        FMLCommonHandler.instance().bus().register(this);
    }

    @SubscribeEvent
    public void onRender(TickEvent.RenderTickEvent e) {
        if (e.phase != TickEvent.Phase.START || state != State.MEASURE) return;
        long now = System.nanoTime();
        if (lastFrame != 0 && n < frames.length) frames[n++] = now - lastFrame;
        lastFrame = now;
    }

    @SubscribeEvent
    public void onClientTick(TickEvent.ClientTickEvent e) {
        if (e.phase != TickEvent.Phase.END) return;
        try {
            step();
        } catch (Throwable t) {
            fail("bench step failed: " + t);
        }
    }

    private void step() throws Exception {
        long now = System.nanoTime();
        if (mc == null) {
            bind();
            firstTick = now;
        }
        double inState = (now - stateSince) / 1e9;
        switch (state) {
            case MENU:
                // The main menu (or the client's own menu) is up and no world is loaded.
                if (currentScreen.get(mc) != null && theWorld.get(mc) == null && (now - firstTick) / 1e9 > 3) {
                    menuMs = sinceJvmStart();
                    log("main menu after " + menuMs + " ms, opening world '" + WORLD + "'");
                    launchWorld.invoke(mc, WORLD, WORLD, null);
                    to(State.LOADING);
                }
                break;
            case LOADING:
                if (theWorld.get(mc) != null && thePlayer.get(mc) != null) {
                    worldMs = sinceJvmStart();
                    log("in the world after " + worldMs + " ms, warming up " + WARMUP_S + " s");
                    to(State.WARMUP);
                } else if (inState > 300) {
                    fail("the world did not load in 5 minutes");
                }
                break;
            case WARMUP:
                turn();
                if (inState >= WARMUP_S) {
                    n = 0;
                    lastFrame = 0;
                    log("measuring " + MEASURE_S + " s");
                    to(State.MEASURE);
                }
                break;
            case MEASURE:
                turn();
                if (inState >= MEASURE_S) {
                    to(State.DONE);
                    finish();
                }
                break;
            default:
                break;
        }
    }

    // A full circle every 6 s: 3 degrees per game tick (20 ticks/s), the same in every run.
    private void turn() throws Exception {
        Object p = thePlayer.get(mc);
        if (p == null) return;
        float y = yaw.getFloat(p);
        prevYaw.setFloat(p, y);
        yaw.setFloat(p, y + 3f);
    }

    private void finish() throws Exception {
        if (n == 0) {
            // No frame in the measure window (a zero-second smoke run): an error result, and the client
            // still shuts down — it used to stay in the world until run.py's timeout.
            write("{\"error\":\"no frames were measured\"}");
            log("no frames were measured");
            shutdown.invoke(mc);
            return;
        }
        long[] s = Arrays.copyOf(frames, n);
        Arrays.sort(s);
        double sum = 0;
        for (long v : s) sum += v;
        double meanMs = sum / 1e6 / n;
        // 1 % low: the average FPS of the slowest 1 % of frames.
        int k = Math.max(1, n / 100);
        double slow = 0;
        for (int i = n - k; i < n; i++) slow += s[i];
        String json = String.format(Locale.ROOT,
                "{\"menu_ms\":%d,\"world_ms\":%d,\"frames\":%d,\"avg_fps\":%.2f,\"low1_fps\":%.2f,"
                        + "\"p50_ms\":%.3f,\"p99_ms\":%.3f,\"p999_ms\":%.3f,\"max_ms\":%.3f,\"measure_s\":%.1f}",
                menuMs, worldMs, n, 1000.0 / meanMs, 1e9 / (slow / k), s[n / 2] / 1e6, s[(int) (n * 0.99)] / 1e6,
                s[Math.min(n - 1, (int) (n * 0.999))] / 1e6, s[n - 1] / 1e6, MEASURE_S);
        write(json);
        log("result " + json);
        shutdown.invoke(mc);
    }

    private void fail(String why) {
        if (state == State.DONE) return;
        state = State.DONE;
        log(why);
        write("{\"error\":\"" + why.replace("\"", "'") + "\"}");
        try {
            if (shutdown != null) shutdown.invoke(mc);
        } catch (Throwable ignored) {
            Runtime.getRuntime().halt(3);
        }
    }

    private void to(State s) {
        state = s;
        stateSince = System.nanoTime();
    }

    private static long sinceJvmStart() {
        return System.currentTimeMillis() - ManagementFactory.getRuntimeMXBean().getStartTime();
    }

    private void write(String json) {
        File out = new File(System.getProperty("mcbench.out", "mebet-bench-result.json"));
        try (Writer w = new OutputStreamWriter(new FileOutputStream(out), StandardCharsets.UTF_8)) {
            w.write(json);
        } catch (Exception e) {
            log("could not write " + out + ": " + e);
        }
    }

    private static void log(String s) {
        System.out.println("[MebetBench] " + s);
    }

    // ---- Minecraft by reflection --------------------------------------------------------------

    private void bind() throws Exception {
        Class<?> mcc = Class.forName("net.minecraft.client.Minecraft");
        for (Method m : mcc.getDeclaredMethods()) {
            if (Modifier.isStatic(m.getModifiers()) && m.getParameterTypes().length == 0 && m.getReturnType() == mcc) {
                m.setAccessible(true);
                mc = m.invoke(null);  // Minecraft.getMinecraft()
            }
        }
        if (mc == null) throw new IllegalStateException("Minecraft.getMinecraft() not found");
        currentScreen = fieldOfType(mcc, "net.minecraft.client.gui.GuiScreen");
        theWorld = fieldOfType(mcc, "net.minecraft.client.multiplayer.WorldClient");
        thePlayer = fieldOfType(mcc, "net.minecraft.client.entity.EntityClientPlayerMP");
        Class<?> ws = Class.forName("net.minecraft.world.WorldSettings");
        launchWorld = mcc.getDeclaredMethod(name(mcc, "func_71371_a", "launchIntegratedServer"), String.class, String.class, ws);
        launchWorld.setAccessible(true);
        shutdown = mcc.getDeclaredMethod(name(mcc, "func_71400_g", "shutdown"));
        shutdown.setAccessible(true);
        Class<?> entity = Class.forName("net.minecraft.entity.Entity");
        yaw = field(entity, "field_70177_z", "rotationYaw");
        prevYaw = field(entity, "field_70126_B", "prevRotationYaw");
    }

    private static Field fieldOfType(Class<?> owner, String type) throws Exception {
        Class<?> t = Class.forName(type);
        for (Field f : owner.getDeclaredFields()) {
            if (f.getType() == t) {
                f.setAccessible(true);
                return f;
            }
        }
        throw new IllegalStateException("no field of type " + type + " in " + owner.getName());
    }

    // The runtime (SRG) name when the client is obfuscated, the readable one in a dev environment.
    private static String name(Class<?> owner, String srg, String plain) {
        for (Method m : owner.getDeclaredMethods()) if (m.getName().equals(srg)) return srg;
        return plain;
    }

    private static Field field(Class<?> owner, String srg, String plain) throws Exception {
        Field f;
        try {
            f = owner.getDeclaredField(srg);
        } catch (NoSuchFieldException e) {
            f = owner.getDeclaredField(plain);
        }
        f.setAccessible(true);
        return f;
    }
}
