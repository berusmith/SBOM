import { useState } from "react";
import { Eye, EyeOff } from "lucide-react";

export function PasswordInput({ value, onChange, placeholder, className = "", error }) {
  const [show, setShow] = useState(false);

  return (
    <div className="relative">
      <input
        type={show ? "text" : "password"}
        value={value}
        onChange={onChange}
        placeholder={placeholder}
        className={`border rounded px-3 py-2 pr-9 text-sm w-full focus:outline-none focus:ring-2 ${
          error ? "border-red-400 focus:ring-red-400" : "border-gray-300 focus:ring-blue-400"
        } ${className}`}
      />
      <button
        type="button"
        onClick={() => setShow(!show)}
        className="absolute right-3 top-2.5 text-gray-600 hover:text-gray-600 p-0.5"
        tabIndex={-1}
        aria-label={show ? "隱藏密碼" : "顯示密碼"}
      >
        {show ? <EyeOff size={16} /> : <Eye size={16} />}
      </button>
      {error && <p className="text-xs text-red-500 mt-1">{error}</p>}
    </div>
  );
}
