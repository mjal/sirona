<script setup>
import { computed } from "vue";

const props = defineProps(["state"]);
const election = props.state.setup?.payload.election;
const countBallots = props.state.ballots?.length;
const fingerprint = props.state.setup?.fingerprint;

console.log(election);
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin" v-if="election">
    <h3 class="uk-card-title">{{ election.name }}</h3>
    <p>{{ election.description }}</p>
    <p>Election UUID: {{ election.uuid }}</p>
    <p>Election fingerprint: {{ fingerprint }}</p>
    <p>Number of ballots: {{ countBallots }}</p>
  </div>

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
