searchForm = document.querySelector('.search-form');

document.querySelector('#search-btn').onclick = () =>{
    searchForm.classList.toggle('active');
}

//menu exlore bottom navbar

let exploreBottom = document.querySelector('#explore-bottom');
exploreBottom.onclick = () =>{
    document.querySelector('.explore-more').classList.toggle('active');
}

//menu exlore bottom navbar

// login

let loginForm = document.querySelector('.login-form-container');

document.querySelector('#login-btn').onclick = () =>{
    loginForm.classList.toggle('active');
}

document.querySelector('#close-login-btn').onclick = () =>{
    loginForm.classList.remove('active');
}

// login

// signup

let signForm = document.querySelector('.signup-form-container');

document.querySelector('#createone-btn').onclick = () =>{
    signForm.classList.toggle('active');
    loginForm.classList.remove('active');
}

document.querySelector('#signup-btn').onclick = () =>{
    signForm.classList.toggle('active');
}

document.querySelector('#close-signup-btn').onclick = () =>{
    signForm.classList.remove('active');
}

document.querySelector('#signin-btn').onclick = () =>{
    loginForm.classList.toggle('active');
    signForm.classList.remove('active');
}

// signup

window.onscroll = () =>{

    searchForm.classList.remove('active');

    if(window.scrollY > 80){
        document.querySelector('.header .header-2').classList.add('active');
    } else {
        document.querySelector('.header .header-2').classList.remove('active');
    }

}

window.onload = () =>{

    if(window.scrollY > 80){
        document.querySelector('.header .header-2').classList.add('active');
    } else {
        document.querySelector('.header .header-2').classList.remove('active');
    }
    fadeOut();
}

// productdetails

let mainImg = document.getElementById('mainimg');
let smallImg = document.getElementsByClassName('small-img');

smallImg[0].onclick = function(){
    mainImg.src = smallImg[0].src;
}
smallImg[1].onclick = function(){
    mainImg.src = smallImg[1].src;
}
smallImg[2].onclick = function(){
    mainImg.src = smallImg[2].src;
}
smallImg[3].onclick = function(){
    mainImg.src = smallImg[3].src;
}

// productdetails

// footer

function loader(){
    document.querySelector('.loader-container').classList.add('active');
}

function fadeOut(){
    setTimeout(loader, 4000);
}

// footer

//load more products

let box = document.querySelectorAll('.products .product-container .box');
let loadmore = document.querySelector('#load-more');
let currentItem = 8;

for (var i=0; i<8; i++){
    box[i].style.display = 'inline-block';
}

loadmore.onclick = () =>{
    for (var i=currentItem; i< currentItem+8; i++){
        box[i].style.display = 'inline-block'
    }
    currentItem += 8;

    if (currentItem >= box.length){
        loadmore.style.display = 'none';
    }
}

//load more products