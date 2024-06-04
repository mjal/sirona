<script setup>
import { ref } from "vue";
import untar from "js-untar";
import check from "./check.js";

const state = ref({});
const loading = ref(false);
const loaded = ref(false);

const onUploadedFile = (event) => {
  const reader = new window.FileReader();
  reader.onload = function () {
    loading.value = true;
    untar(reader.result).then(async (files) => {
      state.value = await check(files);
      loaded.value = true;
      loading.value = false;
      return state;
    });
  };
  reader.readAsArrayBuffer(event.target.files[0]);
};
</script>

<template>
  <div class="uk-container uk-container-xsmall uk-padding">
    <h1 class="uk-h2 uk-text-center">Belenios election verifier</h1>

    <div
      id="import"
      class="uk-card uk-card-body uk-width-medium uk-margin uk-margin-auto"
    >
      <h3 class="uk-card-title">Import your .bel file</h3>

      <div class="js-upload" uk-form-custom>
        <input
          type="file"
          id="file"
          placeholder="Import your .bel file"
          @change="onUploadedFile"
        />
        <button
          class="uk-button uk-button-default uk-margin-top"
          type="button"
          tabindex="-1"
        >
          Import
        </button>
      </div>
    </div>

    <!-- show spinner if loading -->
    <div id="spinner" class="uk-text-center uk-margin" v-if="loading">
      <span uk-spinner="ratio: 4.5" class="uk-margin-auto"></span>
    </div>

    <div id="alerts"></div>

    <div id="actions" class="uk-hidden uk-margin">
      <button
        id="find-your-ballot"
        class="uk-button uk-button-default"
        type="button"
      >
        Find your ballot
      </button>
      <button
        uk-toggle="target: #generate-ballot-modal"
        class="uk-button uk-button-default"
        type="button"
      >
        Generate a ballot
      </button>
    </div>

    <ul uk-tab>
      <li><a href="#">Verifications</a></li>
      <li><a href="#">Election infos</a></li>
      <li><a href="#">Ballots</a></li>
    </ul>

    <!-- Tab Contents -->
    <ul class="uk-switcher uk-margin">
      <li>
        <h3 id="top"></h3>
        <div id="database"></div>
        <div id="setup"></div>
        <div id="ballots"></div>
        <div id="encryptedTally"></div>
        <div id="partialDecryptions"></div>
        <div id="result"></div>
      </li>
      <li>
        <div id="election-info"></div>
        <div id="election-results"></div>
      </li>
      <li>
        <input
          id="ballot-search"
          placeholder="Search a ballot by smart tracker id"
          class="uk-input uk-margin"
          type="text"
        />
        <ul id="ballot-list" class="uk-list uk-list-disc"></ul>
      </li>
    </ul>
  </div>

  <!-- Generate ballot modal -->
  <div class="uk-modal p-6" id="generate-ballot-modal" uk-modal>
    <div class="uk-modal-body uk-modal-dialog">
      <h2 class="uk-modal-title">Generate a ballot</h2>
      <div class="uk-form-stacked uk-margin">
        <div id="generate-ballot-form"></div>

        <div class="uk-margin">
          <label class="uk-form-label" for="generate-ballot-ballot"
            >Your ballot</label
          >
          <textarea
            id="generate-ballot-ballot"
            class="uk-textarea"
            rows="5"
            placeholder="Textarea"
            aria-label="Textarea"
            style="white-space: pre-wrap"
            readonly
          ></textarea>
        </div>
      </div>
      <button class="uk-modal-close uk-button uk-button-default" type="button">
        Close
      </button>
    </div>
  </div>
</template>

<style scoped></style>
