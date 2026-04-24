package io.github.xiaotong6666.fusehide;

public final class MainThreadTask implements Runnable {
    private final int taskKind;
    private final Object target;

    public MainThreadTask(int taskKind, Object target) {
        this.taskKind = taskKind;
        this.target = target;
    }

    @Override
    public void run() {
        if (taskKind == 0) {
            ((Entry) target).registerStatusReceiver();
        } else {
            ((MainActivity) target).onHookCheckTimeout();
        }
    }
}
