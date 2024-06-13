/*
 * This software is licensed under the GNU Affero General Public License (AGPL).
 * By using, modifying, or distributing this software, you agree to the terms and conditions of the AGPL.
 * A copy of the license can be found in the LICENSE file.
 *
 * When useful we use the hungarian notation for variable names.
 * It helps quickly know if a variable is an array, a number, curve point,
 * hex string, or something else.
 * Here are the prefixes:
 *
 * - a for arrays
 * - n for BigInt
 * - p for curve points
 * - h for hexadecimal strings
 * - s for other strings
 */

import { createApp } from "vue";

import "./vendor/franken-ui-0.0.13.min.css";
import "./vendor/uikit.css";
import "./vendor/uikit.js";
import "./vendor/uikit-icons.js";

import App from "./components/App.vue";

createApp(App).mount("#app");
