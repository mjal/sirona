<script setup>
  // Define props state
  defineProps(["state"]);
</script>

<template>
  <div class="uk-card uk-card-default uk-card-body uk-margin">
    <h3 class="uk-card-title"><%- name %></h3>
    <p><%- description %></p>
    <p>Election UUID: <%- uuid %></p>
    <p>Election fingerprint: <%- fingerprint %></p>
    <p>Number of ballots: <%- countBallots %></p>
  </div>
</template>
