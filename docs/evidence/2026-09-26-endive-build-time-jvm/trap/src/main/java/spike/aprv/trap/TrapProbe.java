package spike.aprv.trap;

import run.endive.runtime.Instance;

/** Spike only. One instance of the trap-probe module on its build-time-compiled classes. */
public final class TrapProbe {
    private final Instance instance;

    public TrapProbe() {
        instance = Instance.builder(TrapModule.load()).withMachineFactory(TrapModule::create).build();
    }

    public long call(String name, long... args) {
        long[] r = instance.export(name).apply(args);
        return r == null || r.length == 0 ? 0 : r[0];
    }

    public Instance instance() {
        return instance;
    }
}
