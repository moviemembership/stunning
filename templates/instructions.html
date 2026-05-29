{% extends "base.html" %}
{% block content %}

<style>
body{background:#081120;font-family:Arial,sans-serif;margin:0;color:white;}
.page{max-width:1150px;margin:40px auto;padding:20px;}
h1{text-align:center;color:#EE4D2D;font-size:40px;margin-bottom:10px;}
p{text-align:center;color:#9ca3af;margin-bottom:25px;}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:26px;margin-top:30px;}
.card{background:#0e162e;border:1px solid #1f2b4a;border-radius:24px;padding:24px;text-align:center;transition:.25s;color:white;}
.card:hover{transform:translateY(-6px);border-color:#EE4D2D;box-shadow:0 18px 35px rgba(238,77,45,.22);}
.option-img,.img{width:100%;height:360px;background:#1f2937;border-radius:18px;overflow:hidden;margin-bottom:18px;}
.img{max-width:520px;margin:20px auto;}
.option-img img,.img img{width:100%;height:100%;object-fit:contain;cursor:zoom-in;display:block;}
.box{background:#0e162e;border:1px solid #1f2b4a;border-radius:24px;padding:35px;margin-top:25px;display:none;}
.step{text-align:center;font-size:22px;line-height:1.7;}
.btnrow{display:flex;justify-content:space-between;margin-top:30px;gap:12px;}
button,.btn,.choose-btn{border:none;border-radius:12px;padding:14px 24px;font-weight:800;cursor:pointer;text-decoration:none;display:inline-block;}
.prev{background:#374151;color:white;}
.next,.choose-btn{background:#EE4D2D;color:white;margin-top:10px;}
.image-popup{position:fixed;inset:0;background:rgba(0,0,0,.88);display:none;align-items:center;justify-content:center;z-index:9999;padding:20px;}
.image-popup.active{display:flex;}
.image-popup img{max-width:96%;max-height:96%;border-radius:20px;}
@media(max-width:768px){h1{font-size:30px}.option-img{height:300px}.box{padding:22px}}
</style>

<div class="page">

<h1 id="mainTitle">What does your screen look like?</h1>
<p>Tap the option that matches your Netflix screen.</p>

<div id="devicePage" class="grid">
  <div class="card">
    <div class="option-img"><img src="/test/mobile2.png" onclick="openPopup(this.src)"></div>
    <h2>Phone / PC Screen</h2>
    <button class="choose-btn" onclick="chooseScreenType('phoneStyle')">Choose This</button>
  </div>

  <div class="card">
    <div class="option-img"><img src="/test/smarttvsignin.png" onclick="openPopup(this.src)"></div>
    <h2>TV / QR Screen</h2>
    <button class="choose-btn" onclick="chooseScreenType('tvStyle')">Choose This</button>
  </div>
</div>

<div id="stepBox" class="box">
  <h1 id="guideTitle"></h1>
  <div id="stepImage"></div>
  <div class="step" id="stepText"></div>
  <div class="btnrow">
    <button class="prev" onclick="prevStep()">Previous</button>
    <button class="next" onclick="nextStep()">Next</button>
  </div>
</div>

<div id="optionBox" class="box">
  <h1>Choose Sign In Method</h1>
  <div class="grid" id="optionGrid"></div>
  <div class="btnrow">
    <button class="prev" onclick="backToStep()">Previous</button>
  </div>
</div>

<div id="resultBox" class="box">
  <h1 id="resultTitle"></h1>
  <div id="resultImages"></div>
  <div class="step" id="resultText"></div>
  <div class="btnrow">
    <button class="prev" onclick="backToOptions()">Previous</button>
  </div>
</div>

<div id="imagePopup" class="image-popup" onclick="closePopup()">
  <img id="popupImage" src="">
</div>

</div>

<script>
let flow="";
let step=0;

const guides={
  tvFlow:[
    "Open Netflix on your TV.",
    "Choose Sign In.",
    "Choose how you want to sign in."
  ]
};

const stepImages={
  tvFlow:[
    "/test/mobile1.png",
    "/test/smarttvsignin.png",
    "/test/smarttvoption.png"
  ]
};

function hideAll(){
  devicePage.style.display="none";
  stepBox.style.display="none";
  optionBox.style.display="none";
  resultBox.style.display="none";
}

function chooseScreenType(type){
  if(type==="phoneStyle"){
    flow="phoneFlow";
    showOptions();
  }else{
    flow="tvFlow";
    step=0;
    hideAll();
    stepBox.style.display="block";
    showStep();
  }
}

function showStep(){
  guideTitle.innerText="TV Setup";
  stepText.innerText=guides[flow][step];
  stepImage.innerHTML=`
    <div class="img">
      <img src="${stepImages[flow][step]}" onclick="openPopup(this.src)">
    </div>`;
}

function nextStep(){
  if(step<guides[flow].length-1){
    step++;
    showStep();
  }else{
    showOptions();
  }
}

function prevStep(){
  if(step>0){
    step--;
    showStep();
  }else{
    hideAll();
    devicePage.style.display="grid";
  }
}

function showOptions(){
  hideAll();
  optionBox.style.display="block";

  if(flow==="phoneFlow"){
    optionGrid.innerHTML=`
      <div class="card">
        <div class="option-img"><img src="/test/usesignincode.png" onclick="openPopup(this.src)"></div>
        <h2>Sign-In Code</h2>
        <a class="choose-btn" href="/sign-in-code-auto">Choose This</a>
      </div>

      <div class="card">
        <div class="option-img"><img src="/test/mobilepassword.png" onclick="openPopup(this.src)"></div>
        <h2>Password</h2>
        <button class="choose-btn" onclick="showResult('password')">Choose This</button>
      </div>

      <div class="card">
        <div class="option-img"><img src="/test/somethingwentwrong.png" onclick="openPopup(this.src)"></div>
        <h2>Error Screen</h2>
        <button class="choose-btn" onclick="showResult('wrong')">Choose This</button>
      </div>`;
  }else{
    optionGrid.innerHTML=`
      <div class="card">
        <div class="option-img"><img src="/test/smarttvphoneoption.png" onclick="openPopup(this.src)"></div>
        <h2>Scan QR</h2>
        <button class="choose-btn" onclick="showResult('qr')">Choose This</button>
      </div>

      <div class="card">
        <div class="option-img"><img src="/test/smarttvremote.png" onclick="openPopup(this.src)"></div>
        <h2>Use Remote</h2>
        <button class="choose-btn" onclick="showResult('remote')">Choose This</button>
      </div>`;
  }
}

function showResult(type){
  hideAll();
  resultBox.style.display="block";

  if(type==="password"){
    resultTitle.innerText="Use Password";
    resultImages.innerHTML=`<div class="img"><img src="/test/mobilehowtopassword.png" onclick="openPopup(this.src)"></div>`;
    resultText.innerHTML=
      "1. Tap <b>Get Help</b>.<br><br>2. Tap <b>Use Password</b>.<br><br>3. Enter your password.<br><br>" +
      `<a class="choose-btn" href="/verification-code">It asks me to verify</a>`;
  }

  if(type==="wrong"){
    resultTitle.innerText="Error Screen";
    resultImages.innerHTML=`<div class="img"><img src="/test/somethingwentwrong.png" onclick="openPopup(this.src)"></div>`;
    resultText.innerHTML="Snap a clear photo and send it to customer service.";
  }

  if(type==="qr"){
    resultTitle.innerText="Scan QR";
    resultImages.innerHTML=`<div class="img"><img src="/test/smarttvscanqr.png" onclick="openPopup(this.src)"></div>`;
    resultText.innerHTML="1. Open phone camera.<br><br>2. Scan QR on TV.<br><br>3. Tap the link and follow steps.";
  }

  if(type==="remote"){
    resultTitle.innerText="Use Remote";
    resultImages.innerHTML=`
      <div class="grid">
        <div class="option-img"><img src="/test/smarttvpassword2.png" onclick="openPopup(this.src)"></div>
        <div class="option-img"><img src="/test/smarttvpassword.png" onclick="openPopup(this.src)"></div>
      </div>`;
    resultText.innerHTML="1. Enter email.<br><br>2. Choose <b>Use Password Instead</b>.<br><br>3. Click <b>Next</b> and type password.";
  }
}

function backToStep(){
  hideAll();
  if(flow==="phoneFlow"){
    devicePage.style.display="grid";
  }else{
    stepBox.style.display="block";
  }
}

function backToOptions(){
  hideAll();
  optionBox.style.display="block";
}

function openPopup(src){
  popupImage.src=src;
  imagePopup.classList.add("active");
}

function closePopup(){
  imagePopup.classList.remove("active");
}
</script>

{% endblock %}
