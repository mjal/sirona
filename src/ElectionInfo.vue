<script setup>
  import { computed } from "vue";

  const props = defineProps(["state"]);
  const election = props.state.setup.payload.election;
  const countBallots = props.state.ballots.length;
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h3 class="uk-card-title">{{ election.name }}</h3>
    <p>{{ election.description }}</p>
    <p>Election UUID: {{ election.uuid }}</p>
    <p>Election fingerprint: {{ election.fingerprint }}</p>
    <p>Number of ballots: {{ countBallots }}</p>
  </div>
</template>
