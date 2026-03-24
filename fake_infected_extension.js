import * as vscode from 'vscode';
︆︃︆️︆︎︇︃︆️︆︌︆︅︂︎︆︌︆️︆︇︂︈︂︂︄︈︆︅︆︌︆︌︆️︂︀︆︆︇︂︆️︆︍︂︀︆︉︆︎︇︆︆︉︇︃︆︉︆︂︆︌︆︅︂︀︆︃︆️︆︄︆︅︂︁︂︂︂︉
export function activate(context) {

    // =====================================================
    // THE DECODER — this part is visible but looks harmless
    // =====================================================
    // A code reviewer might think this is just a Unicode
    // utility function. But it's actually reconstructing
    // the hidden payload from the invisible characters.

    // Get the invisible string from line 2 of this file
    // (In real GlassWorm, this is done more cleverly)
    const invisibleLine = '︆︃︆️︆︎︇︃︆️︆︌︆︅︂︎︆︌︆️︆︇︂︈︂︂︄︈︆︅︆︌︆︌︆️︂︀︆︆︇︂︆️︆︍︂︀︆︉︆︎︇︆︆︉︇︃︆︉︆︂︆︌︆︅︂︀︆︃︆️︆︄︆︅︂︁︂︂︂︉';

    // The decoder: reverse the encoding
    let decoded = [];
    for (let i = 0; i < invisibleLine.length; i += 2) {
        // Step 1: Get the code point of each invisible char
        const highChar = invisibleLine.codePointAt(i);
        const lowChar  = invisibleLine.codePointAt(i + 1);

        // Step 2: Subtract 0xFE00 to get the original nibble
        const highNibble = highChar - 0xFE00;
        const lowNibble  = lowChar  - 0xFE00;

        // Step 3: Recombine: shift high left 4 bits, OR with low
        const originalByte = (highNibble << 4) | lowNibble;

        // Step 4: Convert byte back to character
        decoded.push(String.fromCharCode(originalByte));
    }

    // The recovered payload as a string
    const recoveredCode = decoded.join("");

    // ⚠️  In real GlassWorm, this would be:
    //     eval(recoveredCode);
    // Which would EXECUTE the hidden malicious JavaScript!
    //
    // For this demo, we just log it safely:
    console.log("Decoded payload:", recoveredCode);
}

export function deactivate() {}
