import { useEffect, useRef } from "react";

/**
 * Trap keyboard focus inside a container while it is "active".
 *
 * Behavior (matches the WAI-ARIA modal-dialog pattern):
 *   - When `active` flips true:
 *       1. Capture the currently-focused element so we can restore later.
 *       2. Lock body scroll so the modal doesn't drag the page along.
 *       3. Move initial focus to either `initialFocusRef.current` (if
 *          provided) or the first focusable child of the container.
 *   - While active:
 *       - Tab cycles within the container (Shift+Tab on first → last;
 *         Tab on last → first).
 *       - Escape calls `onEscape` if provided.
 *   - When `active` flips false (or component unmounts):
 *       - Body scroll restored.
 *       - Focus returned to whatever held it before activation, if that
 *         node still exists in the DOM.
 *
 * Usage:
 *   const ref = useRef(null);
 *   useFocusTrap({ active: isOpen, containerRef: ref, onEscape: onClose,
 *                  initialFocusRef: cancelButtonRef });
 *   return <div ref={ref} role="dialog" ...>{children}</div>;
 *
 * Notes:
 *   - The hook reads `document.activeElement` at activation time, so the
 *     element that opened the modal will be re-focused on close (matters
 *     for keyboard users so they don't lose their place in the page).
 *   - We deliberately query the focusable list each Tab keystroke rather
 *     than caching it: modal contents can change (e.g. an error message
 *     appears, a "type-to-confirm" input is conditionally rendered) and
 *     a stale list would jam the trap.
 */
const FOCUSABLE_SELECTOR =
  'input:not([disabled]), button:not([disabled]), [href], select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export function useFocusTrap({ active, containerRef, onEscape, initialFocusRef }) {
  const previouslyFocusedRef = useRef(null);

  // Capture previous focus + lock scroll + set initial focus.
  useEffect(() => {
    if (!active) return;

    previouslyFocusedRef.current = document.activeElement;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    // Defer focus until refs are wired (next microtask).
    const focusTimer = window.setTimeout(() => {
      if (initialFocusRef?.current?.focus) {
        initialFocusRef.current.focus();
        return;
      }
      const node = containerRef?.current;
      if (!node) return;
      const focusables = node.querySelectorAll(FOCUSABLE_SELECTOR);
      if (focusables.length > 0) {
        focusables[0].focus();
      } else if (typeof node.focus === "function") {
        node.focus();
      }
    }, 0);

    return () => {
      window.clearTimeout(focusTimer);
      document.body.style.overflow = prevOverflow;
      const prev = previouslyFocusedRef.current;
      if (prev && document.body.contains(prev) && typeof prev.focus === "function") {
        prev.focus();
      }
    };
  }, [active, containerRef, initialFocusRef]);

  // Tab cycle + Escape handler.
  useEffect(() => {
    if (!active) return;
    const handleKey = (e) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onEscape?.();
        return;
      }
      if (e.key !== "Tab") return;
      const node = containerRef?.current;
      if (!node) return;
      const focusables = node.querySelectorAll(FOCUSABLE_SELECTOR);
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", handleKey);
    return () => document.removeEventListener("keydown", handleKey);
  }, [active, containerRef, onEscape]);
}
