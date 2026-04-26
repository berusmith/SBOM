import i18n from "i18next";
import { initReactI18next } from "react-i18next";
import zh from "./zh";
import en from "./en";

const saved = localStorage.getItem("lang") || "zh";

i18n
  .use(initReactI18next)
  .init({
    resources: {
      zh: { translation: zh },
      en: { translation: en },
    },
    lng: saved,
    fallbackLng: "zh",
    interpolation: {
      escapeValue: false,  // React already escapes
    },
  });

// UX-001 — keep <html lang> synchronised with the active UI language so
// screen readers (VoiceOver, NVDA, JAWS, TalkBack) pick the correct
// pronunciation engine. Use BCP-47 tags: zh-Hant (Traditional Chinese)
// and en. Fires on every languageChanged plus once at boot.
const syncHtmlLang = (lng) => {
  const tag = lng === "en" ? "en" : "zh-Hant";
  if (typeof document !== "undefined") {
    document.documentElement.lang = tag;
  }
};
syncHtmlLang(i18n.language);
i18n.on("languageChanged", syncHtmlLang);

export default i18n;
