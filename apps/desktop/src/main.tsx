import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./app/App";
import { CaptureProvider } from "./app/capture";
import { ImportProvider } from "./app/imported";
import { ProfileProvider } from "./app/profile";
import { SessionProvider } from "./app/session";
import { SelectionProvider } from "./app/selection";
import { I18nProvider } from "./i18n";
import "./styles/global.css";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <I18nProvider>
      <ProfileProvider>
        <CaptureProvider>
          <ImportProvider>
            <SessionProvider>
              <SelectionProvider>
                <App />
              </SelectionProvider>
            </SessionProvider>
          </ImportProvider>
        </CaptureProvider>
      </ProfileProvider>
    </I18nProvider>
  </StrictMode>,
);
