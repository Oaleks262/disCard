// ScannerManager.js - Code scanning functionality
class ScannerManager {
  constructor(app) {
    this.app = app;
    this.currentStream = null;
    this.scannerInterval = null;
    this.scanAttempts = 0;
  }

  async openScanner() {
    // Check if browser supports camera
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      UIUtils.showToast('error', UIUtils.safeT('messages.cameraNotSupported', 'Камера не підтримується'));
      return;
    }

    // Check if we're in PWA mode and provide early guidance
    const isStandalone = window.matchMedia('(display-mode: standalone)').matches || 
                        window.navigator.standalone || 
                        document.referrer.includes('android-app://');
    
    if (isStandalone) {
      console.log('🎯 Running in PWA standalone mode - camera permissions may need manual setup');
    }

    // Check if required scanning libraries are available
    const selectedCodeType = document.querySelector('input[name="codeType"]:checked')?.value || 'qrcode';
    const requiredLibrary = selectedCodeType === 'qrcode' ? 'jsQR' : 'Quagga';
    
    if (selectedCodeType === 'qrcode' && typeof jsQR === 'undefined') {
      UIUtils.showToast('error', 'Бібліотека сканування QR-кодів не завантажена');
      return;
    }
    
    if (selectedCodeType === 'barcode' && typeof Quagga === 'undefined') {
      UIUtils.showToast('error', 'Бібліотека сканування штрих-кодів не завантажена');
      return;
    }

    const modal = document.getElementById('scanner-modal');
    const video = document.getElementById('scanner-video');
    const instructions = modal.querySelector('.scanner-instructions');
    
    // Update instructions based on selected code type
    const instructionText = selectedCodeType === 'qrcode' ? 
      'Наведіть камеру на QR-код для сканування' : 
      'Наведіть камеру на штрих-код для сканування';
    
    instructions.textContent = instructionText;
    
    modal.classList.add('show');

    try {
      // Check for PWA standalone mode
      const isStandalone = window.matchMedia('(display-mode: standalone)').matches || 
                          window.navigator.standalone || 
                          document.referrer.includes('android-app://');
      
      // Detect mobile device for optimized settings
      const isMobile = /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
      
      console.log('Camera access attempt:', { isStandalone, isMobile, userAgent: navigator.userAgent });
      
      // Check camera permissions first, especially important for PWA
      if (isStandalone && navigator.permissions) {
        try {
          const permissionStatus = await navigator.permissions.query({ name: 'camera' });
          console.log('Camera permission status:', permissionStatus.state);
          
          if (permissionStatus.state === 'denied') {
            throw new Error('CameraPermissionDenied');
          }
        } catch (permError) {
          console.warn('Could not check camera permissions:', permError);
        }
      }
      
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { 
          facingMode: 'environment',
          width: { ideal: isMobile ? 640 : 1280 },
          height: { ideal: isMobile ? 480 : 720 },
          frameRate: { ideal: isMobile ? 15 : 30 }
        }
      });

      video.srcObject = stream;
      this.currentStream = stream;
      
      // Wait for video to be ready
      await new Promise((resolve) => {
        video.onloadedmetadata = resolve;
      });
      
      // Start scanning
      this.startScanning(video);
      
    } catch (error) {
      console.error('Camera error:', error);
      this.handleCameraError(error);
    }
  }

  handleCameraError(error) {
    console.error('Camera error details:', error);
    
    // Check if we're in PWA mode
    const isStandalone = window.matchMedia('(display-mode: standalone)').matches || 
                        window.navigator.standalone || 
                        document.referrer.includes('android-app://');
    
    let errorMessage = 'Помилка доступу до камери';
    
    if (error.message === 'CameraPermissionDenied' || error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError') {
      if (isStandalone) {
        errorMessage = 'Доступ до камери заборонено. Для PWA додатку:\n\n📱 iOS: Налаштування → Safari → Камера → Дозволити\n🤖 Android: Налаштування додатку → Дозволи → Камера';
      } else {
        errorMessage = 'Доступ до камери заборонено. Дозвольте доступ в налаштуваннях браузера';
      }
    } else if (error.name === 'NotFoundError' || error.name === 'DevicesNotFoundError') {
      errorMessage = 'Камера не знайдена на пристрої';
    } else if (error.name === 'NotReadableError' || error.name === 'TrackStartError') {
      if (isStandalone) {
        errorMessage = 'Камера зайнята. Закрийте інші додатки що використовують камеру і спробуйте знову';
      } else {
        errorMessage = 'Камера зайнята іншою програмою';
      }
    } else if (error.name === 'OverconstrainedError' || error.name === 'ConstraintNotSatisfiedError') {
      errorMessage = 'Камера не підтримує необхідні параметри';
    } else if (error.name === 'NotSupportedError') {
      errorMessage = 'Браузер не підтримує доступ до камери';
    } else if (error.name === 'SecurityError') {
      errorMessage = 'Доступ до камери заблоковано з міркувань безпеки. Переконайтеся, що сайт використовує HTTPS';
    }

    // Show error with retry option for PWA permission issues
    if (isStandalone && (error.message === 'CameraPermissionDenied' || error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError')) {
      UIUtils.showToast('error', errorMessage + '\n\nПісля надання дозволу натисніть "Сканувати" знову');
    } else {
      UIUtils.showToast('error', errorMessage);
    }
    
    this.closeScanner();
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
    
    // Detect mobile device for optimized scanning
    const isMobile = /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);

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
    }, isMobile ? 300 : 200); // Slower scanning on mobile to save battery
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
      console.error('QR scanning error:', error);
    }
    return false;
  }

  // Barcode scanning method
  scanBarcode(canvas) {
    if (typeof Quagga === 'undefined') {
      console.error('Quagga library not loaded');
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
      console.error('Barcode scanning error:', error);
    }
    return false;
  }

  onCodeScanned(code, type) {
    this.closeScanner();
    
    // Fill the form with validated code
    const codeInput = document.getElementById('card-code');
    const filteredCode = code.replace(/[^A-Za-z0-9\-\s]/g, '');
    
    if (code !== filteredCode) {
      UIUtils.showToast('warning', 'Код містив недозволені символи, вони були видалені');
    }
    
    codeInput.value = filteredCode;
    
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
    
    // Scanner option switches
    document.getElementById('camera-option')?.addEventListener('click', this.switchToCamera.bind(this));
    document.getElementById('image-option')?.addEventListener('click', this.switchToImage.bind(this));
    
    // Image upload handlers
    document.getElementById('image-drop-zone')?.addEventListener('click', this.triggerImageUpload.bind(this));
    document.getElementById('image-input')?.addEventListener('change', this.handleImageUpload.bind(this));
    
    // Drag and drop handlers
    this.setupDragAndDrop();
  }

  switchToCamera() {
    document.getElementById('camera-option').classList.add('active');
    document.getElementById('image-option').classList.remove('active');
    document.getElementById('camera-scanner').style.display = 'block';
    document.getElementById('image-scanner').style.display = 'none';
    
    // Start camera if not already running
    if (!this.currentStream) {
      this.startCamera();
    }
  }

  switchToImage() {
    document.getElementById('camera-option').classList.remove('active');
    document.getElementById('image-option').classList.add('active');
    document.getElementById('camera-scanner').style.display = 'none';
    document.getElementById('image-scanner').style.display = 'block';
    
    // Stop camera
    this.stopCamera();
  }

  triggerImageUpload() {
    document.getElementById('image-input').click();
  }

  setupDragAndDrop() {
    const dropZone = document.getElementById('image-drop-zone');
    if (!dropZone) return;

    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
      });
    });

    ['dragenter', 'dragover'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => {
        dropZone.classList.add('dragover');
      });
    });

    ['dragleave', 'drop'].forEach(eventName => {
      dropZone.addEventListener(eventName, () => {
        dropZone.classList.remove('dragover');
      });
    });

    dropZone.addEventListener('drop', (e) => {
      const files = e.dataTransfer.files;
      if (files.length > 0) {
        this.processImageFile(files[0]);
      }
    });
  }

  handleImageUpload(event) {
    const file = event.target.files[0];
    if (file) {
      this.processImageFile(file);
    }
  }

  async processImageFile(file) {
    if (!file.type.startsWith('image/')) {
      UIUtils.showToast('error', 'Будь ласка, оберіть файл зображення');
      return;
    }

    const canvas = document.getElementById('image-canvas');
    const ctx = canvas.getContext('2d');
    
    try {
      // Create image element
      const img = new Image();
      
      img.onload = () => {
        // Set canvas size to image size
        canvas.width = img.width;
        canvas.height = img.height;
        
        // Draw image on canvas
        ctx.drawImage(img, 0, 0);
        
        // Show canvas
        canvas.style.display = 'block';
        
        // Try to scan the image
        this.scanImageOnCanvas(canvas);
      };
      
      img.onerror = () => {
        UIUtils.showToast('error', 'Помилка завантаження зображення');
      };
      
      // Convert file to data URL
      const reader = new FileReader();
      reader.onload = (e) => {
        img.src = e.target.result;
      };
      reader.readAsDataURL(file);
      
    } catch (error) {
      console.error('Image processing error:', error);
      UIUtils.showToast('error', 'Помилка обробки зображення');
    }
  }

  scanImageOnCanvas(canvas) {
    const selectedCodeType = document.querySelector('input[name="codeType"]:checked')?.value || 'qrcode';
    
    try {
      if (selectedCodeType === 'qrcode') {
        this.scanQRFromCanvas(canvas);
      } else {
        this.scanBarcodeFromCanvas(canvas);
      }
    } catch (error) {
      console.error('Image scanning error:', error);
      UIUtils.showToast('error', 'Не вдалося знайти код на зображенні');
    }
  }

  scanQRFromCanvas(canvas) {
    if (typeof jsQR === 'undefined') {
      UIUtils.showToast('error', 'Бібліотека сканування QR-кодів не завантажена');
      return;
    }

    const ctx = canvas.getContext('2d');
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(imageData.data, imageData.width, imageData.height);

    if (code) {
      this.onCodeScanned(code.data, 'qrcode');
    } else {
      UIUtils.showToast('error', 'QR-код не знайдено на зображенні');
    }
  }

  scanBarcodeFromCanvas(canvas) {
    if (typeof Quagga === 'undefined') {
      UIUtils.showToast('error', 'Бібліотека сканування штрих-кодів не завантажена');
      return;
    }

    Quagga.decodeSingle({
      decoder: {
        readers: ["code_128_reader", "ean_reader", "ean_8_reader", "code_39_reader"]
      },
      locate: true,
      src: canvas.toDataURL()
    }, (result) => {
      if (result && result.codeResult) {
        this.onCodeScanned(result.codeResult.code, 'barcode');
      } else {
        UIUtils.showToast('error', 'Штрих-код не знайдено на зображенні');
      }
    });
  }

  startCamera() {
    // Extract camera starting logic from openScanner
    this.openScanner();
  }

  stopCamera() {
    if (this.currentStream) {
      this.currentStream.getTracks().forEach(track => track.stop());
      this.currentStream = null;
    }
    if (this.scannerInterval) {
      clearInterval(this.scannerInterval);
      this.scannerInterval = null;
    }
  }
}

// Export for use in other modules
window.ScannerManager = ScannerManager;