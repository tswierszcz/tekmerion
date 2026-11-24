package ex.pkg;

import java.util.function.Supplier;

public abstract class Sample {
    private final String name;

    public Sample(String name) {
        this.name = name;
    }

    public String greet(String who) {
        String s = "hello " + who;
        return s + " from " + name;
    }

    public long sum(long a, double b) {
        return a + (long) b + 5000000000L;
    }

    protected abstract void hook();

    public Supplier<String> later() {
        return () -> name;
    }

    public static class Inner {
        int twice(int x) {
            return 2 * x;
        }
    }
}

class Helper {
    static void run() {
    }
}
