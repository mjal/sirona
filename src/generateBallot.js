function generateBallot(data) {
}

export function setupGenerateBallotCallback () {
  window.generateBallot = function (event) {
    event.preventDefault();
    const formData = new FormData(event.target);
    const data = {};
    formData.forEach((value, key) => { data[key] = value; });
    console.log(data);
    const ballot = generateBallot(data);
    console.log(ballot);
  }
}

export default function (state) {

}
