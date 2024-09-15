<script setup>
import { computed } from "vue";
import Question from "./Question.vue";
import * as Election from "../Election";

const props = defineProps(["state"]);
const election = props.state.setup?.election;
const countBallots = props.state.ballots?.length;

const electionFingerprint = computed(() => {
  return Election.fingerprint(election);
});

const hasResult = props.state.result ? true : false;
</script>

<template>
  <table class="uk-table uk-table-striped">
    <caption>
      Election infos
    </caption>
    <tbody>
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
        <td>Verification Status</td>
        <td>
          <span class="uk-label uk-label-success">Success</span>
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
        <Question :index="index" :question="question" />
      </template>
    </ul>
  </template>
</template>
