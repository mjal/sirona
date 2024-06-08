<script setup>
const props = defineProps(["state", "ballot"]);
const ballot = props.ballot;
const isTallied = !!props.state.encryptedTally;
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h3 class="uk-card-title">Ballot tracker: {{ ballot.tracker }}</h3>
    <div>
      <span>Status: </span>
      <template v-if="isTallied">
        <span class="uk-badge uk-badge-success" v-if="ballot.accepted"
          >Accepted</span
        >
        <span class="uk-badge uk-badge-danger" v-else>Obselete</span>
      </template>
      <template v-else>
        <span class="uk-badge uk-badge-warning">Pending</span>
      </template>
    </div>
  </div>
</template>
