var swiper = new Swiper(".home-slider", {
    spaceBetween: 30,
    centeredSlides: true,
    autoplay: {
      delay: 2000,
      disableOnInteraction: false,
    },
    pagination: {
      el: ".swiper-pagination",
      clickable: true,
    },
    loop: true,
});

var swiper = new Swiper(".featured-slider", {
    spaceBetween: 10,
    loop:true,
    centeredSlides: true,
    autoplay: {
      delay: 9500,
      disableOnInteraction: false,
    },
    navigation: {
      nextEl: ".swiper-button-next",
      prevEl: ".swiper-button-prev",
    },
    breakpoints: {
      0: {
        slidesPerView: 1,
      },
      450: {
        slidesPerView: 2,
      },
      768: {
        slidesPerView: 3,
      },
      1024: {
        slidesPerView: 4,
      },
    },
});


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

// footer

function loader(){
    document.querySelector('.loader-container').classList.add('active');
}

function fadeOut(){
    setTimeout(loader, 3000);
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
        box[i].style.display = 'inline-block';
    }
    currentItem += 8;

    if (currentItem >= box.length){
        loadmore.style.display = 'none';
    }
}

//load more products




