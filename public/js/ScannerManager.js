// ScannerManager.js - Code scanning functionality
class ScannerManager {
  constructor(app) {
    this.app = app;
    this.currentStream = null;
    this.scannerInterval = null;
    this.scanAttempts = 0;
  }

  async openScanner() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      UIUtils.showToast('error', UIUtils.safeT('messages.cameraNotSupported', 'Камера не підтримується'));
      return;
    }

    const modal = document.getElementById('scanner-modal');
    const video = document.getElementById('scanner-video');
    const instructions = modal.querySelector('.scanner-instructions');
    
    // Update instructions based on selected code type
    const selectedCodeType = document.querySelector('input[name="codeType"]:checked')?.value || 'qrcode';
    const instructionText = selectedCodeType === 'qrcode' ? 
      'Наведіть камеру на QR-код для сканування' : 
      'Наведіть камеру на штрих-код для сканування';
    
    instructions.textContent = instructionText;
    
    modal.classList.add('show');

    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { 
          facingMode: 'environment',
          width: { ideal: 1280 },
          height: { ideal: 720 }
        }
      });

      video.srcObject = stream;
      this.currentStream = stream;
      
      // Start scanning
      this.startScanning(video);
      
    } catch (error) {
      console.error('Camera error:', error);
      UIUtils.showToast('error', UIUtils.safeT('scanner.permissionDenied', 'Доступ до камери заборонено'));
      this.closeScanner();
    }
  }

  closeScanner() {
    const modal = document.getElementById('scanner-modal');
    modal.classList.remove('show');

    if (this.currentStream) {
      this.currentStream.getTracks().forEach(track => track.stop());
      this.currentStream = null;
    }

    if (this.scannerInterval) {
      clearInterval(this.scannerInterval);
      this.scannerInterval = null;
    }
    
    // Reset scan attempts counter
    this.scanAttempts = 0;
  }

  startScanning(video) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');

    // Get currently selected code type
    const getSelectedCodeType = () => {
      const selectedType = document.querySelector('input[name="codeType"]:checked');
      return selectedType ? selectedType.value : 'qrcode';
    };

    this.scannerInterval = setInterval(() => {
      if (video.readyState === video.HAVE_ENOUGH_DATA) {
        canvas.height = video.videoHeight;
        canvas.width = video.videoWidth;
        context.drawImage(video, 0, 0, canvas.width, canvas.height);
        
        const selectedCodeType = getSelectedCodeType();
        this.scanAttempts = (this.scanAttempts || 0) + 1;
        
        if (selectedCodeType === 'qrcode') {
          // QR Code scanning
          this.scanQRCode(context, canvas);
        } else if (selectedCodeType === 'barcode') {
          // Barcode scanning
          this.scanBarcode(canvas);
        }
      }
    }, 200); // Reduced frequency for better performance
  }

  // QR Code scanning method
  scanQRCode(context, canvas) {
    try {
      const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      
      if (code) {
        this.onCodeScanned(code.data, 'qrcode');
        return true;
      }
    } catch (error) {
      console.warn('QR scanning error:', error);
    }
    return false;
  }

  // Barcode scanning method
  scanBarcode(canvas) {
    if (typeof Quagga === 'undefined') {
      console.error('❌ Quagga library not loaded');
      return false;
    }

    try {
      Quagga.decodeSingle({
        decoder: {
          readers: [
            "code_128_reader",    // Code 128
            "ean_reader",         // EAN-13
            "ean_8_reader",       // EAN-8
            "code_39_reader",     // Code 39
            "code_39_vin_reader", // Code 39 VIN
            "codabar_reader",     // Codabar
            "upc_reader",         // UPC-A
            "upc_e_reader",       // UPC-E
            "i2of5_reader"        // Interleaved 2 of 5
          ]
        },
        locate: true,
        src: canvas.toDataURL('image/png')
      }, (result) => {
        if (result && result.codeResult && result.codeResult.code) {
          this.onCodeScanned(result.codeResult.code, 'barcode');
        }
      });
    } catch (error) {
      console.warn('Barcode scanning error:', error);
    }
    return false;
  }

  onCodeScanned(code, type) {
    this.closeScanner();
    
    // Fill the form
    const codeInput = document.getElementById('card-code');
    codeInput.value = code;
    
    // Select the correct code type if it doesn't match
    const currentCodeType = document.querySelector('input[name="codeType"]:checked')?.value;
    if (currentCodeType !== type) {
      const codeTypeInput = document.querySelector(`input[name="codeType"][value="${type}"]`);
      if (codeTypeInput) {
        codeTypeInput.checked = true;
      }
    }
    
    // Update preview
    this.app.cards.updateCodePreview();
    
    // Update form validation
    this.app.cards.updateFormValidation();
    
    // Show success message with code type
    const typeText = type === 'qrcode' ? 'QR-код' : 'штрих-код';
    UIUtils.showToast('success', `✅ ${typeText} успішно відсканований!`);
    
    // Focus on the name field if it's empty
    const nameInput = document.getElementById('card-name');
    if (!nameInput.value.trim()) {
      setTimeout(() => {
        nameInput.focus();
      }, 500);
    }
  }

  // Setup scanner event listeners
  setupScannerEventListeners() {
    document.getElementById('scan-button')?.addEventListener('click', this.openScanner.bind(this));
    document.getElementById('scanner-close')?.addEventListener('click', this.closeScanner.bind(this));
  }
}

// Export for use in other modules
window.ScannerManager = ScannerManager;