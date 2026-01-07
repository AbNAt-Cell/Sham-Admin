$(document).on('change', '.image-compressor', function (e) {
    const file = e.target.files[0];
    if (!file) return;


    const originalInput = document.getElementById('aiImageUploadOriginal');
    if (originalInput) {
        const dataTransferOriginal = new DataTransfer();
        dataTransferOriginal.items.add(file);
        originalInput.files = dataTransferOriginal.files;
    }

    new Compressor(file, {
        quality: 0.10,
        maxWidth: 800,
        maxHeight: 800,
        mimeType: 'image/jpeg',
        convertSize: Infinity,
        crop: false,
        success(result) {
            const compressedFile = new File([result], file.name.replace(/\.\w+$/, '.jpg'), {
                type: 'image/jpeg',
                lastModified: Date.now()
            });

            console.log("Original size:", (file.size / 1024).toFixed(1), "KB");
            console.log("Compressed size:", (compressedFile.size / 1024).toFixed(1), "KB");

            const dataTransfer = new DataTransfer();
            dataTransfer.items.add(compressedFile);
            e.target.files = dataTransfer.files;
        },
        error(err) {
            console.error('Compression error:', err.message);
        }
    });
});
