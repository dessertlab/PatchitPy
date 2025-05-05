const path = require('path');
const fs = require('fs');
const vscode = require('vscode');
const remediate = require('./Remediation');


const execPatchitpy = require('./execPatchitpy');
const delFile = require('./utilities/deleteFile');
const removePythonComments = require('./utilities/removePythonComments');


function runPatchitpyFromText() {
    return new Promise((resolve, reject) => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            const document = editor.document;
            const selection = editor.selection; //get selected text from file
            let selectedText = document.getText(selection); //get selected text

            const filePath = document.uri.fsPath;
            const fileName = path.basename(filePath);
            const fileDir = path.dirname(filePath);

            const tempFilePath = path.join(fileDir, 'codeFrom_' + fileName);
            
            // Check if the selected text is empty
            if (selectedText.trim() === '') {
                vscode.window.showErrorMessage('[PatchitPy]: No code selected');
                return;
            }
            
            selectedText = "#PatchitPy ADD\n" + selectedText;
            selectedText = removePythonComments(selectedText);
            //console.log(selectedText);

            // Write text in temp-file
            fs.writeFile(tempFilePath, selectedText, (err) => {
                if (err) {
                    vscode.window.showErrorMessage(`Error writing to file: ${err.message}`);
                    return;
                }
            });

            execPatchitpy(tempFilePath)
            .then(() => {
                // Delete the temporary file after execution is complete
                delFile(tempFilePath);
                
                remediate(fileDir, fileName, editor, selection);

                //delete generated files after remediation
         
                resolve(); 
            })
            .catch((err) => {
                vscode.window.showErrorMessage(`[PatchitPy]: Error executing the tool: ${err.message}`);
                reject(err); // Reject promise if there's an error
            });
        
        } else {
            reject(new Error('No active text editor'));
        }

        
    });
}


module.exports = runPatchitpyFromText;