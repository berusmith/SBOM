/**
 * 驗證函式庫
 * 回傳 null = 通過驗證，string = 錯誤訊息
 */

export const validators = {
  required: (value) => {
    return value.trim() ? null : "此欄位為必填";
  },

  minLen: (length) => (value) => {
    return value.length >= length ? null : `至少需 ${length} 字元`;
  },

  username: (value) => {
    if (!value.trim()) return "帳號為必填";
    if (value.length < 3) return "帳號需至少 3 字元";
    if (!/^[a-zA-Z0-9_]+$/.test(value)) return "帳號只能使用英數字和底線";
    return null;
  },

  password: (value) => {
    if (!value) return "密碼為必填";
    if (value.length < 6) return "密碼需至少 6 字元";
    return null;
  },

  passwordOptional: (value) => {
    if (value && value.length < 6) return "密碼需至少 6 字元";
    return null;
  },
};

/**
 * 批量驗證多個欄位
 * @param {Object} rules - { fieldName: validatorFn | [validatorFns...] }
 * @param {Object} values - { fieldName: value }
 * @returns {Object} { fieldName: errorMsg | null }
 */
export function validate(rules, values) {
  const errors = {};

  for (const [field, rule] of Object.entries(rules)) {
    const value = values[field] || "";

    // 如果 rule 是陣列，逐個執行直到有錯誤
    if (Array.isArray(rule)) {
      for (const validator of rule) {
        const error = validator(value);
        if (error) {
          errors[field] = error;
          break;
        }
      }
    } else {
      // 單個 rule
      errors[field] = rule(value);
    }
  }

  return errors;
}
