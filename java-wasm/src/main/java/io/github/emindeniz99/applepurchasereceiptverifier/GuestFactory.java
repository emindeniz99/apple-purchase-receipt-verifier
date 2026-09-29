package io.github.emindeniz99.applepurchasereceiptverifier;

/**
 * Makes instances of the verifier module for one engine. Thread-safe. The
 * Endive engine's implementation is Java 11 bytecode, loaded by name only
 * when that engine is chosen ({@link Engine#endive()}).
 */
interface GuestFactory {

    /**
     * A new instance, not yet {@code init}ed.
     *
     * @throws GuestFailure if the module cannot be instantiated or lacks the
     *     ABI this library binds
     */
    Guest newGuest();

    /** Names the engine and module in messages, such as "Endive 1.1.0, aprv.wasm sha256 ...". */
    String describe();
}
