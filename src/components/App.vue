<script setup>
import { ref } from "vue";
import untar from "js-untar";
import check from "../check.js";
import ElectionInfo from "./ElectionInfo.vue";
import ElectionResult from "./ElectionResult.vue";
import ElectionBallotList from "./ElectionBallotList.vue";
import GenerateBallotModal from "./GenerateBallotModal.vue";

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

const goToBallotList = () => {
  UIkit.tab(document.querySelector(".uk-tab")).show(1);
};
</script>

<template>
  <div class="uk-container uk-container-xsmall uk-padding">
    <h1 class="uk-h2 uk-text-center">Belenios election verifier</h1>

    <div
      id="import"
      class="uk-card uk-card-body uk-width-medium uk-margin uk-margin-auto"
      v-if="!loaded && !loading"
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

    <div id="spinner" class="uk-text-center uk-margin" v-if="loading">
      <span uk-spinner="ratio: 4.5" class="uk-margin-auto"></span>
    </div>

    <div id="alerts"></div>

    <div id="actions" class="uk-margin" v-if="loaded">
      <button
        id="find-your-ballot"
        class="uk-button uk-button-default"
        type="button"
        @click="goToBallotList"
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
      <button
        class="uk-button uk-button-default"
        type="button"
        onclick="window.location.reload();"
      >
        Upload another file
      </button>
    </div>

    <ul uk-tab>
      <li><a href="#">Election infos</a></li>
      <li><a href="#">Ballots</a></li>
      <li><a href="#">Log</a></li>
    </ul>

    <!-- Tab Contents -->
    <ul class="uk-switcher uk-margin">
      <li>
        <div v-if="!loaded">Not loaded yet.</div>
        <ElectionInfo :state="state" v-if="loaded" />
        <ElectionResult :state="state" v-if="loaded && state.result" />
      </li>
      <li>
        <ElectionBallotList :state="state" v-if="loaded" />
      </li>
      <li>
        <h3 id="top"></h3>
        <div id="database"></div>
        <div id="setup"></div>
        <div id="ballots"></div>
        <div id="encryptedTally"></div>
        <div id="partialDecryptions"></div>
        <div id="result"></div>
      </li>
    </ul>
  </div>

  <GenerateBallotModal :state="state" v-if="loaded" />
</template>

<style scoped></style>
