<script setup>
import { computed } from "vue";

const props = defineProps(["state", "logs", "ballotLogs"]);
const election = props.state.setup?.payload.election;
const countBallots = props.state.ballots?.length;
const fingerprint = props.state.setup?.fingerprint;

const hasResult = props.state.result ? true : false;
const hasError = computed(() => {
  const keys = ["top", "database", "setup", "encryptedTally", "result"];
  const bError = keys.some((key) => {
    return props.logs[key].filter(({pass}) => !pass).length;
  })
  // props.ballotLogs is a hash map
  const bBallotError = Object.values(props.ballotLogs).some((logEntry) => {
    return logEntry.some(({pass}) => !pass);
  });
  return bError || bBallotError;
});

</script>

<template>
    <table class="uk-table uk-table-striped">
      <caption>Election infos</caption>
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
            <span v-if="hasResult" class="uk-label uk-label-success">Finished</span>
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
          <td>{{ fingerprint }}</td>
        </tr>
        <tr>
          <td>Number of ballots</td>
          <td>{{ countBallots }}</td>
        </tr>
      </tbody>
    </table>

  <!--div class="uk-card uk-card-default uk-card-body uk-margin" v-if="election">
  </div-->

  <template v-if="election">
    <template v-for="(question, index) in election.questions" v-bind:key="index">
      <div class="uk-card uk-card-default uk-card-body uk-margin">
        <h3 class="uk-card-title uk-margin">{{ question.question }}</h3>
        <h4 v-for="(answer, index) in question.answers" v-bind:key="index">
          Answer {{ index }} : {{ answer }}
        </h4>
        <div class="uk-margin">
          <p>Selection between {{ question.min }} and {{ question.max }} choices</p>
          <p>{{ question.blank ? "Blank vote allowed" : "Blank vote not allowed" }}</p>
        </div>
      </div>
    </template>
  </template>
</template>
