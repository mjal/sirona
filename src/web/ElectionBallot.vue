<script setup>
import { computed } from "vue";
import * as EncryptedTally from "../EncryptedTally";
import * as Ballot from "../Ballot";

const props = defineProps(["state", "ballot"]);

const isTallied = !!props.state.encryptedTally;

const hash = computed(() => {
  return Ballot.hash(props.ballot);
});

const tracker = computed(() => {
  return Ballot.b64hash(props.ballot);
});

const isAccepted = computed(() => {
  if (!isTallied) {
    return false;
  }
  return EncryptedTally.keepLastBallots(props.state.ballots).find((e) => {
    return Ballot.hash(e) === hash.value;
  });
});
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h5 class="">Ballot tracker: {{ tracker }}</h5>
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
