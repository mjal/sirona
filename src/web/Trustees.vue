<script setup lang="ts">
import { computed } from "vue";
import * as Trustee from "../Trustee";
import * as Point from "../Point";

const props = defineProps<{
  trustees: Trustee.t[];
}>();
</script>

<template>
  <table class="uk-table uk-table-striped">
    <caption>
      Trustees
    </caption>
    <tbody>
      <tr v-for="(trustee, index) in trustees" v-bind:key="index">
        <template v-if="trustee[0] === 'Single'">
          <td>Single</td>
          <td>{{ Trustee.serialize(trustee)[1] }}</td>
        </template>
        <template v-else>
          <td>Pedersen</td>
          <td>{{ Trustee.serialize(trustee)[1] }}</td>
        </template>
      </tr>
    </tbody>
  </table>
</template>
