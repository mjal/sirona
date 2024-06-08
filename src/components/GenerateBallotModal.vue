<script setup>
import generateBallot, { checkVotingCode } from "../generateBallot";
import { ref, computed } from "vue";
import canonicalBallot from "../canonicalBallot.js";

const props = defineProps(["state", "loaded"]);

const questions = computed(() => {
  return props.state.setup ? props.state.setup.payload.election.questions : [];
});

const credential = ref("yXSNB-E8tK7Z-wqffF-pSfWdP");
const serializedGeneratedBallot = ref("");

const submitForm = (event) => {
  event.preventDefault();
  const formData = new FormData(event.target);
  const data = {};
  formData.forEach((value, key) => {
    data[key] = value;
  });

  let answers = [];
  for (let i = 0; i < questions.value.length; i++) {
    const question = questions.value[i];
    const answer = question.answers.map((_answerName, j) => {
      return data[`q-${i}-${j}`] === "on" ? 1 : 0;
    });
    const blank = data[`q-${i}-blank`] === "on" ? 1 : 0;
    const nbAnswers = answer.reduce((a, b) => a + b);

    if (nbAnswers < question.min || nbAnswers > question.max) {
      alert(
        `Question ${i + 1} must have between ${question.min} and ${question.max} answers`,
      );
      return false;
    }

    if (blank && nbAnswers > 0) {
      alert(`Question ${i + 1} cannot have both answers and blank`);
      return false;
    }

    if (question.blank) {
      answers.push([blank, ...answer]);
    } else {
      answers.push(answer);
    }
  }

  const oBallot = generateBallot(props.state, credential.value.trim(), answers);
  const sBallot = JSON.stringify(canonicalBallot(oBallot));
  serializedGeneratedBallot.value = sBallot;
  return false;
};

const checkCode = () => {
  if (checkVotingCode(props.state, credential.value.trim())) {
    alert("Code is valid");
  }
};
</script>

<template>
  <div class="uk-modal p-6" id="generate-ballot-modal" uk-modal>
    <div class="uk-modal-body uk-modal-dialog">
      <h2 class="uk-modal-title">Generate a ballot</h2>
      <div class="uk-form-stacked uk-margin">
        <div id="generate-ballot-form"></div>
        <form @submit.prevent="submitForm">
          <div class="uk-margin">
            <label class="uk-form-label" for="generate-ballot-private-key">
              Code de vote
            </label>
            <div class="uk-form-controls">
              <input
                type="text"
                class="uk-input"
                v-model="credential"
                placeholder="Paste your code"
              />
            </div>

            <button
              class="uk-button uk-button-default"
              type="button"
              @click="checkCode"
            >
              Check
            </button>
          </div>

          <div
            class="uk-margin"
            v-for="(question, i) in questions"
            v-bind:key="i"
          >
            <div class="uk-margin">
              <label class="uk-form-label" v-bind:for="'q-' + i">
                {{ question.question }} (Between {{ question.min }} and
                {{ question.max }} answers)
              </label>

              <div class="uk-form-controls">
                <div v-for="(answer, j) in question.answers" v-bind:key="j">
                  <label>
                    <input type="checkbox" v-bind:name="'q-' + i + '-' + j" />
                    {{ answer }}
                  </label>
                </div>
                <div v-if="question.blank" class="uk-margin">
                  <label>
                    <input type="checkbox" v-bind:name="'q-' + i + '-blank'" />
                    Blank
                  </label>
                </div>
                <hr class="uk-margin" />
              </div>
            </div>
          </div>
          <input
            type="submit"
            class="uk-button uk-button-default"
            value="Generate ballot"
          />
        </form>
        <div class="uk-margin">
          <label class="uk-form-label" for="generate-ballot-ballot"
            >Your ballot</label
          >
          <textarea
            v-model="serializedGeneratedBallot"
            class="uk-textarea"
            rows="5"
            placeholder="Textarea"
            aria-label="Textarea"
            style="white-space: pre-wrap"
            readonly
          ></textarea>
        </div>
      </div>
      <button class="uk-modal-close uk-button uk-button-default" type="button">
        Close
      </button>
    </div>
  </div>
</template>
