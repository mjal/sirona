/*
 * This software is licensed under the GNU Affero General Public License (AGPL).
 * By using, modifying, or distributing this software, you agree to the terms and conditions of the AGPL.
 * A copy of the license can be found in the LICENSE file.
 */

import { createApp } from "vue";

import "./vendor/franken-ui-0.0.13.min.css";
import "./vendor/uikit.css";
import "./vendor/uikit.js";
import "./vendor/uikit-icons.js";

import App from "./components/App.vue";

createApp(App).mount("#app");
