<script setup>
import { ref, reactive, computed } from "vue";
import untar from "js-untar";
import check from "../check";
import LogSection from "./LogSection.vue";
import ElectionInfo from "./ElectionInfo.vue";
import ElectionResult from "./ElectionResult.vue";
import ElectionBallotList from "./ElectionBallotList.vue";
import GenerateBallotModal from "./GenerateBallotModal.vue";
import { getLogs, getBallotLogs } from "../logger";

import { TarReader } from "../tarReader";

const state = ref({});
const logs = ref([]);
const ballotLogs = ref({});
const loading = ref(false);
const loaded = ref(false);

const onUploadedFile = (event) => {
  const reader = new window.FileReader();
  reader.onload = async () => {
    loading.value = true;

    const tarReader = new TarReader(reader.result);

    const files = tarReader.getFiles();
    state.value = await check(files);

    loaded.value = true;
    loading.value = false;
    logs.value = getLogs();
    ballotLogs.value = getBallotLogs();
    return state;
  };
  reader.readAsArrayBuffer(event.target.files[0]);
};

const goToBallotList = () => {
  UIkit.tab(document.querySelector(".uk-tab")).show(1);
};

</script>

<template>
  <div class="uk-container uk-container-xsmall uk-padding">
    <h1 class="uk-h2 uk-text-center">Sirona (a tool for belenios elections)</h1>
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
      <li><a href="#">Verification summary</a></li>
    </ul>

    <!-- Tab Contents -->
    <ul class="uk-switcher uk-margin">
      <li>
        <div v-if="!loaded">Not loaded yet.</div>
        <ElectionInfo :state="state" :logs="logs" :ballotLogs="ballotLogs" v-if="loaded" />
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
        <div id="check2">
          <ul uk-accordion>
            <LogSection v-if="logs.top"
              title="General" :logs="logs.top" />
            <LogSection v-if="logs.database"
              title="Database" :logs="logs.database" />
            <LogSection v-if="logs.setup"
              title="Setup" :logs="logs.setup" />
            <template v-for="(ballotLogEntry, key) in ballotLogs" :key="key">
              <LogSection :title="'Ballot ' + key" :logs="ballotLogEntry" />
            </template>
            <LogSection v-if="logs.encryptedTally"
              title="Encrypted Tally" :logs="logs.encryptedTally" />
            <LogSection v-if="logs.result"
              title="Result" :logs="logs.result" />
          </ul>
        </div>
      </li>
    </ul>
  </div>

  <GenerateBallotModal :state="state" v-if="loaded" />
</template>

<style scoped></style>
