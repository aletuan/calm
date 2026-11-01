import { useI18n } from "../i18n";
import type { ErrorMessage } from "../lib/errorMessage";

/** The plain-language sentence first; a raw code or size, if any, on its own line below. */
export function ErrorText({ message }: { message: ErrorMessage }) {
  const { t } = useI18n();
  return (
    <>
      <p>{t(message.key)}</p>
      {message.detail && (
        <p className="meta error-detail">
          {t("error.detail")}: <span className="mono">{message.detail}</span>
        </p>
      )}
    </>
  );
}

/** Several form errors: one per line, so each sentence can be read on its own. */
export function FormErrors({ messages, className = "" }: { messages: string[]; className?: string }) {
  if (messages.length === 0) return null;
  return (
    <ul className={`form-error ${className}`.trim()} role="alert">
      {messages.map((m) => (
        <li key={m}>{m}</li>
      ))}
    </ul>
  );
}
