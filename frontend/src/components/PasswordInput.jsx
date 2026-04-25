import { useState, useId } from "react";
import { Eye, EyeOff } from "lucide-react";
import { useTranslation } from "react-i18next";

/**
 * Accessible password field with show/hide toggle.
 *
 * - text-base font (16px) so iOS Safari does not auto-zoom on focus.
 * - aria-invalid + aria-describedby wire the error message to the input.
 * - The toggle button is excluded from the default tab order (tabIndex=-1)
 *   so keyboard users moving through the form aren't stopped on a purely
 *   decorative control; it remains reachable by mouse / touch / direct
 *   tab when desired.
 */
export function PasswordInput({
  value,
  onChange,
  placeholder,
  className = "",
  error,
  id,
  name = "password",
  autoComplete = "current-password",
}) {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);
  const generatedId = useId();
  const inputId = id || `pw-${generatedId}`;
  const errId = `${inputId}-err`;

  return (
    <div className="relative">
      <input
        id={inputId}
        name={name}
        type={show ? "text" : "password"}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        autoComplete={autoComplete}
        aria-invalid={error ? "true" : "false"}
        aria-describedby={error ? errId : undefined}
        className={`border rounded px-3 py-2 pr-10 text-base w-full focus:outline-none focus:ring-2 ${
          error ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
        } ${className}`}
      />
      <button
        type="button"
        onClick={() => setShow(!show)}
        className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-700 hover:text-gray-900 p-1.5 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
        tabIndex={-1}
        aria-label={show ? t("common.hidePassword", { defaultValue: "Hide password" })
                         : t("common.showPassword", { defaultValue: "Show password" })}
      >
        {show ? <Eye size={16} aria-hidden="true" /> : <EyeOff size={16} aria-hidden="true" />}
      </button>
      {error && <p id={errId} className="text-xs text-red-600 mt-1">{error}</p>}
    </div>
  );
}
