using System;

namespace CrashLens.Core
{
    public enum Lang { Ko, En, Vi }

    /// <summary>3개 언어(한국어/영어/베트남어) 문자열 선택. 문구는 사용하는 자리에 세 언어를 나란히 적는다.</summary>
    public static class L
    {
        public static Lang Current = Lang.En;

        public static string T(string ko, string en, string vi)
        {
            return Current == Lang.Ko ? ko : Current == Lang.Vi ? vi : en;
        }

        public static string F(string ko, string en, string vi, params object[] args)
        {
            return string.Format(T(ko, en, vi), args);
        }

        /// <summary>Windows 표시 언어 이름(ko-KR, vi-VN 등)에서 기본 언어를 정한다. 그 외는 영어.</summary>
        public static Lang FromCulture(string cultureName)
        {
            var n = (cultureName ?? "").ToLowerInvariant();
            if (n.StartsWith("ko")) return Lang.Ko;
            if (n.StartsWith("vi")) return Lang.Vi;
            return Lang.En;
        }
    }

    /// <summary>정적 표에 넣는 3개 언어 문구. 문자열로 쓰일 때 현재 언어로 바뀐다.</summary>
    public sealed class Tx
    {
        readonly string ko, en, vi;
        public Tx(string ko, string en, string vi) { this.ko = ko; this.en = en; this.vi = vi; }
        public override string ToString() { return L.T(ko, en, vi); }
    }
}
