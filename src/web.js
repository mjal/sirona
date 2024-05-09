import main from "./main.js";
import untar from "js-untar";

document.getElementById("file").addEventListener("change", function() {
  const reader = new FileReader();
  reader.onload = function() {
    untar(reader.result).then(main);
  }
  reader.readAsArrayBuffer(this.files[0]);
})
