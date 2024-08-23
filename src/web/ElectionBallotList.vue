<script setup>
import { ref, computed } from "vue";
import * as Ballot from "../Ballot";
import ElectionBallot from "./ElectionBallot.vue";

const props = defineProps(["state"]);
const ballots = props.state.ballots;
const search = ref("");

const filteredBallots = computed(() => {
  if (!ballots) {
    return [];
  }
  if (!search.value) {
    return ballots;
  }
  return ballots.filter((ballot) => {
    const tracker = Ballot.b64hash(ballot);

    search.value.includes(tracker);
  });
});
</script>

<template>
  <input
    v-model="search"
    id="ballot-search"
    placeholder="Search a ballot by smart tracker id"
    class="uk-input uk-margin"
    type="text"
    @change="filerBallots"
  />
  <ul id="ballot-list" class="">
    <div v-for="(ballot, index) in filteredBallots" :key="index">
      <ElectionBallot :state="state" :ballot="ballot" />
    </div>
  </ul>
</template>
