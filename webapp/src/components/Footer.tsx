// SPDX-FileCopyrightText: (C) 2024 Jason Ish <jason@codemonkey.net>
// SPDX-License-Identifier: MIT

export function Footer() {
  return (
    <footer class="text-center text-muted small mt-4 mb-3">
      <div class="fw-semibold">ООО "НАЙС СОФТ ГРУП"</div>
      <div>
        Работает на <a href="https://niceos.ru" target="_blank" rel="noreferrer">НАЙС.ОС</a>
        Используйте наши другие продукты: <a href="https://yandex.cloud/ru/marketplace?publishers=f2ed90kua4t10varbjh9&tab=software" target="_blank" rel="noreferrer">на Яндекс.Cloud</a>
      </div>
      <div>NiceSoft.Eve © {new Date().getFullYear()}</div>
    </footer>
  );
}
