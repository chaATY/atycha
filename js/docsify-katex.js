(() => {
  var e, r;
  (e = window.$docsify.markdown),
    (r = marked.parse),
    (window.$docsify.markdown = function (n, t) {
      var i = {
          name: "math",
          level: "inline",
          start: function (e) {
            var r;
            return null === (r = e.match(/\$/)) || void 0 === r
              ? void 0
              : r.index;
          },
          tokenizer: function (e, r) {
            var n;
            return (n = /^\$\$((\\.|[^\$\\])+)\$\$/.exec(e))
              ? {
                  type: "math",
                  raw: n[0],
                  text: n[1].trim(),
                  mathLevel: "block",
                }
              : (n = /^\$((\\.|[^\$\\])+)\$/.exec(e))
              ? {
                  type: "math",
                  raw: n[0],
                  text: n[1].trim(),
                  mathLevel: "inline",
                }
              : void 0;
          },
          renderer: function (e) {
            return "block" === e.mathLevel
              ? katex.renderToString(e.text, {
                  throwOnError: !1,
                  displayMode: !0,
                })
              : "inline" === e.mathLevel
              ? katex.renderToString(e.text, {
                  throwOnError: !1,
                  displayMode: !1,
                })
              : void 0;
          },
        },
        o =
          Object.assign ||
          function (e) {
            for (var r = 1; r < arguments.length; r++) {
              var n = Object(arguments[r]);
              for (var t in n) hasOwn.call(n, t) && (e[t] = n[t]);
            }
            return e;
          },
        a = e || {};
      return (
        (a =
          "function" == typeof e
            ? originMarkdonw.apply(this, n, t).defaults
            : o(a, { renderer: o(t, a.renderer) })),
        r.setOptions(a),
        r.use({ extensions: [i] }),
        r
      );
    });
})();
