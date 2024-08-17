<script setup>
import { computed } from "vue";
import * as EncryptedTally from "../EncryptedTally";

const props = defineProps(["state", "ballot"]);
const ballot = props.ballot;
const isTallied = !!props.state.encryptedTally;
const isAccepted = computed(() => {
  if (!isTallied) {
    return false;
  }
  return EncryptedTally.keepLastBallots(props.state.ballots).find(
    (e) => e.payloadHash === ballot.payloadHash,
  );
});
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h5 class="">Ballot tracker: {{ ballot.tracker }}</h5>
    <div>
      <span>Status: </span>
      <template v-if="isTallied">
        <span class="uk-label uk-label-success" v-if="isAccepted">
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
