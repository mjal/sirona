<script setup>
import EncryptedTally from "../EncryptedTally";

const props = defineProps(["state", "ballot"]);
const ballot = props.ballot;
const isTallied = !!props.state.encryptedTally;
const isAccepted = computed(() => {
  if (!isTallied) {
    return false;
  }
  return EncryptedTally.keepLastBallots(props.state.ballots).find((e) => e.payloadHash === ballot.payloadHash);
});
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h3 class="uk-card-title">Ballot tracker: {{ ballot.tracker }}</h3>
    <div>
      <span>Status: </span>
      <template v-if="isTallied">
        <span class="uk-label uk-label-success" v-if="ballot.accepted">
          Accepted
        </span>
        <span class="uk-label uk-label-danger" v-else> Obselete </span>
      </template>
      <template v-else>
        <span class="uk-label"> Pending </span>
      </template>
    </div>
  </div>
</template>
