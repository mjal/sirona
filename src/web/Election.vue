<script setup lang="ts">
import { computed } from "vue";
import * as Election from "../Election";
import * as Point from "../Point";
import Question from "./Question.vue";

const props = defineProps<{
  election: Election.t;
}>();

const electionFingerprint = computed(() => {
  return Election.fingerprint(props.election);
});
</script>

<template>
  <table class="uk-table uk-table-striped">
    <caption>
      Election
    </caption>
    <tbody>
      <tr>
        <td>version</td>
        <td>{{ election.version }}</td>
      </tr>
      <tr>
        <td>description</td>
        <td>{{ election.description }}</td>
      </tr>
      <tr>
        <td>name</td>
        <td>{{ election.name }}</td>
      </tr>
      <tr>
        <td>group</td>
        <td>{{ election.group }}</td>
      </tr>
      <tr>
        <td>public_key</td>
        <td>{{ Point.serialize(election.public_key) }}</td>
      </tr>
      <tr>
        <td>uuid</td>
        <td>{{ election.uuid }}</td>
      </tr>
      <tr v-if="election.administrator">
        <td>administrator</td>
        <td>{{ election.administrator }}</td>
      </tr>
      <tr v-if="election.credential_authority">
        <td>credential_authority</td>
        <td>{{ election.credential_authority }}</td>
      </tr>
    </tbody>
  </table>
  <template v-for="(question, index) in election.questions" v-bind:key="index">
    <Question :index="index" :question="question" />
  </template>
</template>
