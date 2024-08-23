<script setup>
import { computed } from "vue";
import Question from "./Question.vue";
import * as Election from "../Election";

const props = defineProps(["state", "logs", "ballotLogs"]);
const election = props.state.setup?.election;
const countBallots = props.state.ballots?.length;

const electionFingerprint = computed(() => {
  return Election.fingerprint(election);
});

const hasResult = props.state.result ? true : false;
const hasError = computed(() => {
  const keys = ["top", "database", "setup", "encryptedTally", "result"];
  const bError = keys.some((key) => {
    return (
      props.logs[key] && props.logs[key].filter(({ pass }) => !pass).length
    );
  });
  const bBallotError = Object.values(props.ballotLogs).some((logEntry) => {
    return logEntry.some(({ pass }) => !pass);
  });
  return bError || bBallotError;
});
</script>

<template>
  <table class="uk-table uk-table-striped">
    <caption>
      Election infos
    </caption>
    <tbody>
      <tr>
        <td>Verification Status</td>
        <td>
          <span v-if="hasError" class="uk-label uk-label-danger">Error</span>
          <span v-else class="uk-label uk-label-success">Success</span>
        </td>
      </tr>
      <tr>
        <td>Election Status</td>
        <td>
          <span v-if="hasResult" class="uk-label uk-label-success"
            >Finished</span
          >
          <span v-else class="uk-label">In progress</span>
        </td>
      </tr>
      <tr>
        <td>Name</td>
        <td>{{ election.name }}</td>
      </tr>
      <tr>
        <td>Description</td>
        <td>{{ election.description }}</td>
      </tr>
      <tr>
        <td>UUID</td>
        <td>{{ election.uuid }}</td>
      </tr>
      <tr>
        <td>Fingerprint</td>
        <td>{{ electionFingerprint }}</td>
      </tr>
      <tr>
        <td>Number of ballots</td>
        <td>{{ countBallots }}</td>
      </tr>
    </tbody>
  </table>

  <template v-if="election">
    <ul uk-accordion>
      <template
        v-for="(question, index) in election.questions"
        v-bind:key="index"
      >
        <Question :question="question" />
      </template>
    </ul>
  </template>
</template>
