"use strict";


function main() {
    const generateButton = document.getElementById("generateButton");
    const credentialCount = document.getElementById("credentialCount");
    const output = document.getElementById("output");

    generateButton.onclick = () => {
        while (output.rows.length > 1)
            output.deleteRow(1);

        for (let i = 0; i < credentialCount.value; i++) {
            const pair = buidl.createP2PKH();
            const address = pair.addr;
            const privateKey = pair.pk;

            const row = output.insertRow(output.rows.length);

            const partyIdCell = row.insertCell(0);
            partyIdCell.className = "text-align-center";
            partyIdCell.innerHTML = `<b>${String.fromCharCode(65 + (i % 26))}</b>`;

            const credentialsTable = document.createElement("table");

            const addressRow = credentialsTable.insertRow(0);

            const addressLabelCell = addressRow.insertCell(0);
            addressLabelCell.className = "text-align-right";
            addressLabelCell.innerHTML = "<b>Address</b>";

            const addressCell = addressRow.insertCell(1);
            addressCell.className = "monospace text-align-left";
            addressCell.innerText = address;

            const pkRow = credentialsTable.insertRow(1);

            const pkLabelCell = pkRow.insertCell(0);
            pkLabelCell.className = "text-align-right";
            pkLabelCell.innerHTML = "<b>Private Key</b>";

            const pkCell = pkRow.insertCell(1);
            pkCell.className = "monospace text-align-left";
            pkCell.innerText = privateKey;

            row.insertCell(1).appendChild(credentialsTable);

            new QRCode(row.insertCell(2), {
                text: address,
                width: 128,
                height: 128,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
        }
    };

    return 0;
}

window.onload = main;
