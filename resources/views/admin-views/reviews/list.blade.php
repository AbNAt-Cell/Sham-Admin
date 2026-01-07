@extends('layouts.admin.app')

@section('title', translate('Review List'))

@push('css_or_js')
    <meta name="csrf-token" content="{{ csrf_token() }}">
    <link rel="stylesheet" href="{{asset('/public/assets/admin/css/lightbox.min.css')}}">

@endpush

@section('content')
    <div class="content container-fluid">
        <div class="d-flex flex-wrap gap-2 align-items-center mb-4">
            <h2 class="h1 mb-0 d-flex align-items-center gap-2">
                <img width="20" class="avatar-img" src="{{asset('public/assets/admin/img/icons/review.png')}}" alt="">
                <span class="page-header-title">
                    {{translate('product_review')}}
                </span>
            </h2>
        </div>

        <div class="row g-2">
            <div class="col-12">
                <div class="card">
                    <div class="card-top px-card pt-4">
                        <div class="row justify-content-between align-items-center gy-2">
                            <div class="col-sm-4 col-md-6 col-lg-8">
                                <h4>{{translate('review_list')}} <span id="total_count" class="badge badge-soft-dark rounded-50 fz-14">{{ $reviews->total() }}</span></h4>
                            </div>
                            <div class="col-sm-8 col-md-6 col-lg-4">
                                <form action="" method="GET" id="search-form">
                                    @csrf
                                    <div class="input-group">
                                        <input id="datatableSearch_" type="search" name="search" class="form-control" placeholder="{{translate('search_by_product_name')}}" aria-label="Search" value="{{ request()->search }}" required="" autocomplete="off">
                                        <div class="input-group-append">
                                            <button type="submit" class="btn btn-primary">{{translate('search')}}</button>
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                    <div class="py-4">
                        <div class="table-responsive datatable-custom">
                            <table
                                class="table table-borderless table-thead-bordered table-nowrap table-align-middle card-table">
                                <thead class="thead-light">
                                <tr>
                                    <th>{{translate('SL')}}</th>
                                    <th>{{translate('product_name')}}</th>
                                    <th>{{translate('customer_info')}}</th>
                                    <th>{{translate('review')}}</th>
                                    <th>{{translate('rating')}}</th>
                                    <th>{{translate('image')}}</th>
                                </tr>
                                </thead>
                                <tbody id="set-rows">
                                @foreach($reviews as $key=>$review)
                                    <tr>
                                        <td>{{$reviews->firstitem()+$key}}</td>
                                        <td>
                                            <div>
                                                @if($review->product)
                                                    <a class="text-dark media align-items-center gap-2" href="{{route('admin.product.view',[$review['product_id']])}}">
                                                        <div class="avatar">
                                                            <img class="rounded-circle img-fit" src="{{$review->product['imageFullPath']}}" alt="{{ translate('image') }}">
                                                        </div>
                                                        <span class="media-body max-w220 text-wrap">{{$review->product['name']}}</span>
                                                    </a>
                                                @else
                                                    <span class="badge-pill badge-soft-dark text-muted small">
                                                        {{translate('Product unavailable')}}
                                                    </span>
                                                @endif
                                            </div>
                                        </td>
                                        <td>
                                            @if($review->customer)
                                                <div class="d-flex flex-column gap-1">
                                                    <a class="text-dark" href="{{route('admin.customer.view',[$review->user_id])}}">
                                                        {{$review->customer->f_name." ".$review->customer->l_name}}
                                                    </a>
                                                    <a class="text-dark fz-12" href="tel:'{{$review->customer->phone}}'">{{$review->customer->phone}}</a>
                                                </div>
                                            @else
                                                <span class="badge-pill badge-soft-dark text-muted small">
                                                    {{translate('Customer unavailable')}}
                                                </span>
                                            @endif
                                        </td>
                                        <td>
                                            <div class="max-w300 line-limit-3">{{$review->comment}}</div>
                                        </td>
                                        <td>
                                            <label class="badge badge-soft-info">
                                                {{$review->rating}} <i class="tio-star"></i>
                                            </label>
                                        </td>

                                        <td>
                                            <div class="w-100">
                                                    <?php
                                                    $images = [];
                                                    $attachments = json_decode($review['attachment'], true) ?? [];

                                                    foreach ($attachments as $k => $item) {
                                                        if (\Illuminate\Support\Facades\Storage::disk('public')->exists('review/' . $item)) {
                                                            $images[$k] = asset('storage/app/public/review/' . $item);
                                                        } else {
                                                            $images[$k] = asset('public/assets/admin/img/160x160/img2.jpg');
                                                        }
                                                    }
                                                    ?>
                                                @foreach($images as $attachment)
                                                    <a href="{{$attachment}}" data-lightbox >
                                                        <img class="m-1 img-100" src="{{ $attachment }}" alt="Review Image" width="60">
                                                    </a>
                                                @endforeach

                                            </div>
                                        </td>
                                    </tr>
                                @endforeach
                                </tbody>
                            </table>
                        </div>

                        <div class="table-responsive mt-4 px-3">
                            <div class="d-flex justify-content-lg-end">
                                {!! $reviews->links() !!}
                            </div>
                        </div>

                        @if(count($reviews) == 0)
                            <div class="text-center p-4">
                                <img class="w-120px mb-3" src="{{asset('/public/assets/admin/svg/illustrations/sorry.svg')}}" alt="Image Description">
                                <p class="mb-0">{{translate('No_data_to_show')}}</p>
                            </div>
                        @endif
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection

@push('script_2')
    <script>
        "use strict";
        var lightbox = function (o) {
            var s = void 0,
                c = void 0,
                u = void 0,
                d = void 0,
                i = void 0,
                p = void 0,
                m = document,
                e = m.body,
                l = "fadeIn .3s",
                v = "fadeOut .3s",
                t = "scaleIn .3s",
                f = "scaleOut .3s",
                a = "lightbox-btn",
                n = "lightbox-gallery",
                b = "lightbox-trigger",
                g = "lightbox-active-item",
                y = function () {
                    return e.classList.toggle("remove-scroll");
                },
                r = function (e) {
                    if (
                        ("A" === o.tagName && (e = e.getAttribute("href")),
                            e.match(/\.(jpeg|jpg|gif|png)/))
                    ) {
                        var t = m.createElement("img");
                        return (
                            (t.className = "lightbox-image"),
                                (t.src = e),
                            "A" === o.tagName &&
                            (t.alt = o.getAttribute("data-image-alt")),
                                t
                        );
                    }
                    if (e.match(/(youtube|vimeo)/)) {
                        var a = [];
                        return (
                            e.match("youtube") &&
                            ((a.id = e
                                .split(/v\/|v=|youtu\.be\//)[1]
                                .split(/[?&]/)[0]),
                                (a.url = "youtube.com/embed/"),
                                (a.options = "?autoplay=1&rel=0")),
                            e.match("vimeo") &&
                            ((a.id = e
                                .split(/video\/|https:\/\/vimeo\.com\//)[1]
                                .split(/[?&]/)[0]),
                                (a.url = "player.vimeo.com/video/"),
                                (a.options = "?autoplay=1title=0&byline=0&portrait=0")),
                                (a.player = m.createElement("iframe")),
                                a.player.setAttribute("allowfullscreen", ""),
                                (a.player.className = "lightbox-video-player"),
                                (a.player.src = "https://" + a.url + a.id + a.options),
                                (a.wrapper = m.createElement("div")),
                                (a.wrapper.className = "lightbox-video-wrapper"),
                                a.wrapper.appendChild(a.player),
                                a.wrapper
                        );
                    }
                    return m.querySelector(e).children[0].cloneNode(!0);
                },
                h = function (e) {
                    var t = {
                        next: e.parentElement.nextElementSibling,
                        previous: e.parentElement.previousElementSibling,
                    };
                    for (var a in t)
                        null !== t[a] && (t[a] = t[a].querySelector("[data-lightbox]"));
                    return t;
                },
                x = function (e) {
                    p.removeAttribute("style");
                    var t = h(u)[e];
                    if (null !== t)
                        for (var a in ((i.style.animation = v),
                            setTimeout(function () {
                                i.replaceChild(r(t), i.children[0]),
                                    (i.style.animation = l);
                            }, 200),
                            u.classList.remove(g),
                            t.classList.add(g),
                            (u = t),
                            c))
                            c.hasOwnProperty(a) && (c[a].disabled = !h(t)[a]);
                },
                E = function (e) {
                    var t = e.target,
                        a = e.keyCode,
                        i = e.type;
                    ((("click" == i && -1 !== [d, s].indexOf(t)) ||
                        ("keyup" == i && 27 == a)) &&
                    d.parentElement === o.parentElement &&
                    (N("remove"),
                        (d.style.animation = v),
                        (p.style.animation = [f, v]),
                        setTimeout(function () {
                            if ((y(), o.parentNode.removeChild(d), "A" === o.tagName)) {
                                u.classList.remove(g);
                                var e = m.querySelector("." + b);
                                e.classList.remove(b), e.focus();
                            }
                        }, 200)),
                        c) &&
                    ((("click" == i && t == c.next) || ("keyup" == i && 39 == a)) &&
                    x("next"),
                    (("click" == i && t == c.previous) ||
                        ("keyup" == i && 37 == a)) &&
                    x("previous"));
                    if ("keydown" == i && 9 == a) {
                        var l = ["[href]", "button", "input", "select", "textarea"];
                        l = l.map(function (e) {
                            return e + ":not([disabled])";
                        });
                        var n = (l = d.querySelectorAll(l.toString()))[0],
                            r = l[l.length - 1];
                        e.shiftKey
                            ? m.activeElement == n && (r.focus(), e.preventDefault())
                            : (m.activeElement == r && (n.focus(), e.preventDefault()),
                                r.addEventListener("blur", function () {
                                    r.disabled && (n.focus(), e.preventDefault());
                                }));
                    }
                },
                N = function (t) {
                    ["click", "keyup", "keydown"].forEach(function (e) {
                        "remove" !== t
                            ? m.addEventListener(e, function (e) {
                                return E(e);
                            })
                            : m.removeEventListener(e, function (e) {
                                return E(e);
                            });
                    });
                };
            !(function () {
                if (
                    ((s = m.createElement("button")).setAttribute(
                        "aria-label",
                        "Close"
                    ),
                        (s.className = a + " " + a + "-close"),
                        ((i = m.createElement("div")).className = "lightbox-content"),
                        i.appendChild(r(o)),
                        ((p = i.cloneNode(!1)).className = "lightbox-wrapper"),
                        (p.style.animation = [t, l]),
                        p.appendChild(s),
                        p.appendChild(i),
                        ((d = i.cloneNode(!1)).className = "lightbox-container"),
                        (d.style.animation = l),
                        (d.onclick = function () {}),
                        d.appendChild(p),
                    "A" === o.tagName && "gallery" === o.getAttribute("data-lightbox"))
                )
                    for (var e in (d.classList.add(n),
                        (c = { previous: "", next: "" })))
                        c.hasOwnProperty(e) &&
                        ((c[e] = s.cloneNode(!1)),
                            c[e].setAttribute("aria-label", e),
                            (c[e].className = a + " " + a + "-" + e),
                            (c[e].disabled = !h(o)[e]),
                            p.appendChild(c[e]));
                "A" === o.tagName &&
                (o.blur(), (u = o).classList.add(g), o.classList.add(b)),
                    o.parentNode.insertBefore(d, o.nextSibling),
                    y();
            })(),
                N();
        };

        Array.prototype.forEach.call(
            document.querySelectorAll("[data-lightbox]"),
            function (t) {
                t.addEventListener("click", function (e) {
                    e.preventDefault(), new lightbox(t);
                });
            }
        );

    </script>
@endpush


