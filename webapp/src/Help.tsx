// SPDX-FileCopyrightText: (C) 2023 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

import { createSignal, For, Show, Suspense } from "solid-js";
import { Button, Modal, Tab, Tabs } from "solid-bootstrap";
import { closeHelp, showHelp } from "./Top";

import { createResource } from "solid-js";
import { getVersion, SERVER_REVISION } from "./api";
import { GIT_REV } from "./gitrev";

export function HelpModal() {
  const [tab, setTab] = createSignal<string>("keyboard");
  return (
    <Modal show={showHelp()} onHide={closeHelp} size={"lg"}>
      <Modal.Header closeButton>
        <Modal.Title>Справка</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Tabs activeKey={tab()} onSelect={(k) => k && setTab(k as string)} id="help-tabs">
          <Tab eventKey="keyboard" title="Горячие клавиши">
            <Keyboard />
          </Tab>
          <Tab eventKey="about" title="О программе">
            <About />
          </Tab>
        </Tabs>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={closeHelp} aria-label="Закрыть окно справки">
          Закрыть
        </Button>
      </Modal.Footer>
    </Modal>
  );
}

function Keyboard() {
  const key = (k: string) => <span class="font-monospace px-1 py-0.5 border rounded bg-light">{k}</span>;

  const then = (a: string, b: string) => (
    <>
      {key(a)} <span class="fw-lighter">затем</span> {key(b)}
    </>
  );

  const plus = (a: string, b: string) => (
    <>
      {key(a)} <span class="fw-lighter">+</span> {key(b)}
    </>
  );

  const shortcuts: Array<[any, string]> = [
    [key("?"), "Показать справку"],
    [then("g", "i"), "Перейти во входящие"],
    [then("g", "s"), "Перейти в эскалированные"],
    [then("g", "a"), "Перейти к оповещениям"],
    [key("e"), "Архивировать выбранные события или событие под курсором"],
    [key("F8"), "Архивировать событие под курсором"],
    [plus("Shift", "s"), "Эскалировать и архивировать событие под курсором"],
    [key("F9"), "Эскалировать и архивировать событие под курсором"],
    [key("x"), "Выбрать событие под курсором"],
    [key("s"), "Эскалировать выбранные события или событие под курсором"],
    [key("j"), "К следующему событию"],
    [key("k"), "К предыдущему событию"],
    [key("."), "Меню действий для события под курсором"],
    [plus("Control", "\\"), "Сбросить все фильтры и поиск"],
    [plus("Shift", "h"), "Первая строка"],
    [plus("Shift", "g"), "Последняя строка"],
    [then("*", "a"), "Выбрать все оповещения в области видимости"],
    [then("*", "n"), "Снять выделение со всех оповещений"],
    [then("*", "1"), "Выбрать все оповещения с текущим SID"],
  ];

  return (
    <div class="pt-2">
      <table class="table table-bordered table-sm align-middle">
        <tbody>
          <For each={shortcuts}>
            {(e) => (
              <tr>
                <td style={{ "white-space": "nowrap" }}>{e[0]}</td>
                <td>{e[1]}</td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function About() {
  const [version] = createResource(getVersion);

  return (
    <div style="padding: 12px">
      <p class="mb-2 text-muted small">О приложении</p>
      <p>
        <Suspense fallback={<>Загрузка сведений о версии…</>}>
          Версия EveBox {version()?.version} (ревизия: {version()?.revision}).
        </Suspense>
      </p>

      <Show when={SERVER_REVISION() && SERVER_REVISION() !== GIT_REV}>
        <div class="alert alert-danger" role="alert">
          Внимание: версии сервера и фронтенда отличаются. Пожалуйста, обновите страницу.
          <br />
          Сервер = {SERVER_REVISION()}, Фронтенд = {GIT_REV}.
        </div>
      </Show>

      <hr class="my-3" />

      <div class="vstack gap-2">
        <div>
          <strong>Разработчик:</strong>
          <br />ООО «НАЙС СОФТ ГРУП»
        </div>
        <div>
          <strong>Платформа:</strong>
          <br />Работает на {" "}
          <a href="https://niceos.ru" target="_blank" rel="noreferrer">
            НАЙС.ОС
          </a>
        </div>
        <div>
          <strong>Сведения о включении в реестр:</strong>
          <br />Реестровая запись №30128 от 22.10.2025
          <br />Произведена на основании поручения Министерства цифрового развития, связи и массовых коммуникаций Российской Федерации от 22.10.2025 по протоколу заседания экспертного совета от 09.10.2025 №872пр
        </div>
        <div>
          <strong>Наши продукты:</strong>
          <br />Доступны в каталоге
          {" "}
          <a
            href="https://yandex.cloud/ru/marketplace?publishers=f2ed90kua4t10varbjh9&tab=software"
            target="_blank"
            rel="noreferrer"
          >
            на Яндекс.Cloud
          </a>
        </div>
      </div>
    </div>
  );
}
