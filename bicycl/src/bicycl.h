#pragma once


#include <gmp.h>

#include <stdexcept>
#include <string>
#include <algorithm>
#include <vector>
#include <iostream>
#include <cstddef>
#include <tuple>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h> /* for NID_* */
#include <openssl/rand.h>

//#ifdef BICYCL_WITH_PTHREADS
#include <thread>
//#endif

//#include "bicycl/gmp_extras.hpp"
namespace BICYCL
{
    namespace _gmp_impl
    {
#if 0
        static inline void
    mpz_invert_2exp_scratch (mpz_ptr r, mpz_srcptr a, mp_bitcnt_t n, mpz_ptr t)
    {
      mpz_set_ui (r, 1);
      for (size_t i = 1; i < n; i <<= 1)
      {
        mpz_set_ui (t, 2);
        mpz_submul (t, r, a);
        mpz_mul (t, r, t);
        mpz_fdiv_r_2exp (r, t, i << 1);
      }
    }

    /*
     * Input: a, r and n
     *
     * Output: set r to a modulo 2^n with r in ]-2^(n-1), 2^(n-1)]
     *
     * Assumption:
     *    - n >= 1
     *
     */
    static inline void
    mpz_mod_with_centered_remainder_2exp (mpz_ptr r, mpz_srcptr a,
                                          mp_bitcnt_t n)
    {
        mpz_fdiv_r_2exp (r, a, n);

        /* substract 2^n if needed */
        if (mpz_tstbit (r, n-1))
        {
          mpn_com (r->_mp_d, r->_mp_d, r->_mp_size);
          mpz_add_ui (r, r, 1);
          mpz_fdiv_r_2exp (r, r, n);
          mpz_neg_inplace (r);
        }
    }
#endif
    } /* _gmp_impl namespace */

    /* forward declaration, needed to declare it friend of Mpz */
    class RandGen;

    class Mpz
    {
    protected:
        mpz_t mpz_;

    public:
        /* constructors */
        Mpz ();
        Mpz (const Mpz &);
        Mpz (Mpz &&);
        explicit Mpz (unsigned long);
        explicit Mpz (long);
        explicit Mpz (const std::string &);
        explicit Mpz (mpf_srcptr);
        explicit Mpz (const BIGNUM *);
        Mpz (const std::vector<unsigned char> &, size_t);

        /* destructor */
        ~Mpz ();

        /* assignment */
        Mpz & operator= (const Mpz &);
        Mpz & operator= (Mpz &&);
        Mpz & operator= (unsigned long);
        Mpz & operator= (long);
        Mpz & operator= (const std::string &);
        Mpz & operator= (mpf_srcptr); /* only needed once in ClassGroup */
        Mpz & operator= (const BIGNUM *);

        /* comparison */
        bool operator== (const Mpz &) const;
        bool operator!= (const Mpz &) const;
        bool operator< (const Mpz &) const;
        bool operator> (const Mpz &) const;
        bool operator<= (const Mpz &) const;
        bool operator>= (const Mpz &) const;
        bool operator== (unsigned long) const;
        bool operator!= (unsigned long) const;
        bool operator< (unsigned long) const;
        bool operator> (unsigned long) const;
        bool operator<= (unsigned long) const;
        bool operator>= (unsigned long) const;
        bool operator== (long) const;
        bool operator!= (long) const;
        bool operator< (long) const;
        bool operator> (long) const;
        bool operator<= (long) const;
        bool operator>= (long) const;

        /* conversion */
        explicit operator mpz_srcptr() const;
        explicit operator unsigned long() const;
        explicit operator long() const;

        /* getters */
        /* */
        size_t nbits () const;
        size_t ndigits () const;
        size_t nlimbs () const;
        int sgn () const;
        std::string str_value() const;

        /* tests */
        bool is_zero () const;
        bool is_odd () const;
        bool is_even () const;
        bool is_one () const;
        bool is_prime (int reps=30) const;
        bool is_divisible_by (const Mpz &d) const;

        /* misc */
        void neg ();
        mp_limb_t extract_bits (size_t, size_t) const;
        int tstbit (size_t) const;
        void setbit (size_t);
        unsigned long mod4 () const;
        unsigned long mod8 () const;
        size_t val2 () const;
        void nextprime ();
        int legendre (const Mpz &) const;
        int jacobi (const Mpz &) const;
        int kronecker (const Mpz &) const;

        void to_bytes(std::vector<unsigned char> &dst) const {
            size_t size = (mpz_sizeinbase(mpz_, 2) + 8 - 1) / 8;
            dst.resize(size);
            mpz_export(dst.data(), NULL, 1, 1, 0, 0, mpz_);
        }

        bool is_equal(const Mpz & other) const {
            return *this == other;
        }

        /* */
        static void swap (Mpz &, Mpz &);
        // 构造方法Mpz (const Mpz &);无法自动生成接口，用此方法代替
        inline static Mpz copy_from(const Mpz &v) {
            return Mpz(v);
        }

        /* arithmetic */
        static void abs (Mpz &, const Mpz &);
        static int cmpabs (const Mpz &, const Mpz &);

        static void add (Mpz &, const Mpz &, const Mpz &);
        static void add (Mpz &, const Mpz &, unsigned long);

        static void sub (Mpz &, const Mpz &, const Mpz &);
        static void sub (Mpz &, const Mpz &, unsigned long op2);

        static void mul (Mpz &, const Mpz &, const Mpz &);
        static void mul (Mpz &, const Mpz &, unsigned long);
        static void mulby2k (Mpz &, const Mpz &, mp_bitcnt_t k);
        static void mulby2k (Mpz &, unsigned long, mp_bitcnt_t k);
        static void mulby2 (Mpz &, const Mpz &);
        static void mulby4 (Mpz &, const Mpz &);

        static void addmul (Mpz &, const Mpz &, const Mpz &);
        static void submul (Mpz &, const Mpz &, const Mpz &);

        static void divby2k (Mpz &, const Mpz &, mp_bitcnt_t k);
        static void divby2 (Mpz &, const Mpz &);
        static void divby4 (Mpz &, const Mpz &);
        static void divexact (Mpz &, const Mpz &, const Mpz &);
        static void divexact (Mpz &, const Mpz &, unsigned long);
        static void cdiv_qr (Mpz &, Mpz &, const Mpz &, const Mpz &);
        static void fdiv_qr (Mpz &, Mpz &, const Mpz &, const Mpz &);

        static void mod (Mpz &, const Mpz &, const Mpz &);
        static void mod2k (Mpz &, const Mpz &, mp_bitcnt_t);
        static void mod2k_centered (Mpz &, const Mpz &, mp_bitcnt_t);
        // TODO inverse -> invert
        static void mod_inverse (Mpz &, const Mpz &, const Mpz &);
        static void mod_inverse_2k (Mpz &, const Mpz &, mp_bitcnt_t k);
        static void mod_inverse_2k (Mpz &, const Mpz &, mp_bitcnt_t k, Mpz &);
        static void pow (Mpz &, const Mpz &, unsigned long int);
        static void pow_mod (Mpz &, const Mpz &, const Mpz &, const Mpz &);
        static void pow_mod (Mpz &, const Mpz &, const Mpz &, const Mpz &,
                             size_t, const Mpz &, const Mpz &, const Mpz &);

        static void gcd (Mpz &, const Mpz &, const Mpz &);
        static void gcdext (Mpz &, Mpz &, Mpz &, const Mpz &, const Mpz &);
        static void lcm (Mpz &, const Mpz &, const Mpz &);
        static void sqrt (Mpz &, const Mpz &);
        static void root4th (Mpz &, const Mpz &);
        static void sqrt_mod_prime (Mpz &, const Mpz &, const Mpz &);

        static size_t remove (Mpz &, const Mpz &, const Mpz &);

        /* */
        static void CRT (Mpz &, const Mpz &, const Mpz &, const Mpz &,
                         const Mpz &);

        /* */
        static void ceil_abslog_square (Mpz &, const Mpz &);

        /* */
        static void partial_euclid (Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &,
                                    mp_size_t, Mpz &, Mpz &);
        static void partial_euclid (Mpz &, Mpz &, Mpz &u10, Mpz &u11, Mpz &,
                                    Mpz &, mp_size_t);

        /* I/O */
        friend std::ostream & operator<< (std::ostream &, const Mpz &);
        friend std::istream & operator>> (std::istream &, Mpz &);

        /* exception */
        class ModInverseException;

    protected:
        static int richcmp (const Mpz &, const Mpz &);
        static int richcmp (const Mpz &, unsigned long);
        static int richcmp (const Mpz &, long);

        friend RandGen;
    }; /* Mpz class */


    class RandGen
    {
    protected:
        gmp_randstate_t rand_;

    public:
        RandGen ();
        RandGen (const RandGen &);
        RandGen (const Mpz &);
        ~RandGen ();

        RandGen copy() const {
            return RandGen(*this);
        }

        void set_seed (const Mpz &);

        Mpz random_mpz (const Mpz &);
        Mpz random_mpz_2exp (mp_bitcnt_t);

        unsigned char random_uchar ();
        unsigned long random_ui (unsigned long);
        unsigned long random_ui_2exp (mp_bitcnt_t);

        Mpz random_negative_discriminant (mp_bitcnt_t);

        bool random_bool ();

        Mpz random_prime (mp_bitcnt_t);
    }; /* RandGen */


    /* */
    class JSF : protected std::vector<uint8_t>
    {
    public:
        using std::vector<uint8_t>::size;

        JSF (const Mpz &n0, const Mpz &n1);

        uint8_t operator[] (size_t i) const;

    protected:
        void set (size_t i, int d0, int d1);
    };

//  #include "gmp_extras.inl"
/*
 * GMP internal macros copied from gmp-impl.h.
 * Should be undef at the end of header
 */
#define ALLOC(x) ((x)->_mp_alloc)
#define PTR(x) ((x)->_mp_d)
#define SIZ(x) ((x)->_mp_size)
#define ABS(x) ((x) >= 0 ? (x) : -(x))
#define ABSIZ(x) ABS (SIZ (x))

#define GMP_NUMB_HIGHBIT  (((mp_limb_t) 1) << (GMP_NUMB_BITS-1))

#define MPN_EXTRACT_NUMB(count, xh, xl)                       \
    ((((xh) << ((count) - GMP_NAIL_BITS)) & GMP_NUMB_MASK) |  \
    ((xl) >> (GMP_LIMB_BITS - (count))))

#define MPN_NORMALIZE(DST, NLIMBS) do {   \
    while ((NLIMBS) > 0)                  \
    {                                     \
      if ((DST)[(NLIMBS) - 1] != 0)       \
        break;                            \
      (NLIMBS)--;                         \
    }                                     \
  } while (0)


/*
 * Should be undef at the end of header
 * Note: ideally we want to get the same definition as in longlong.h from GMP,
 * but there is a lot of cases depending on architectures and compilers. For
 * example, for gcc, it uses __builtin_clzll. To be generic, we need to use
 * mpz_sizeinbase.
 * Warning: x must be a variable, not a constant, as we take its address.
 */
//#define count_leading_zeros(count, x) (count) = __builtin_clzll((x))
#define count_leading_zeros(count, x) (count) = GMP_LIMB_BITS - mpn_sizeinbase (&(x), 1, 2)

#define mpn_hgcd2 __MPN(hgcd2)
#define mpn_matrix22_mul1_inverse_vector __MPN(matrix22_mul1_inverse_vector)
#define mpn_hgcd_mul_matrix1_vector __MPN (hgcd_mul_matrix1_vector)
#define mpn_binvert __MPN (binvert)
#define mpn_binvert_itch __MPN (binvert_itch)
#define mpn_redc_n __MPN (redc_n)

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
    namespace
    {
        /*
         * GMP internal struct copied from gmp-impl.h.
         */
        struct hgcd_matrix1
        {
            mp_limb_t u[2][2];
        };

        /*
         * GMP internal functions, defined in gmp-impl.h, implemented in mpn/ files,
         * exported in libgmp but not defined in gmp.h.
         */
        extern "C"
        {
        extern
        int mpn_hgcd2 (mp_limb_t, mp_limb_t, mp_limb_t, mp_limb_t,
                       struct hgcd_matrix1 *);
        extern
        mp_size_t mpn_matrix22_mul1_inverse_vector (const struct hgcd_matrix1 *,
                                                    mp_ptr, mp_srcptr, mp_ptr,
                                                    mp_size_t);
        extern
        mp_size_t mpn_hgcd_mul_matrix1_vector (const struct hgcd_matrix1 *, mp_ptr,
                                               mp_srcptr, mp_ptr, mp_size_t);
        extern
        void mpn_binvert (mp_ptr rp, mp_srcptr up, mp_size_t n, mp_ptr scratch);
        extern
        mp_size_t mpn_binvert_itch (mp_size_t n);
        extern
        void mpn_redc_n (mp_ptr rp, mp_ptr up, mp_srcptr mp, mp_size_t n,
                         mp_srcptr ip);
        }

        /*
         * Return the 2*GMP_NUMB_BITS most significant bits of ap and bp.
         * It assumes that one of ap[n-1] or bp[n-1] is nonzero.
         * If l = max (log2(ap), log2(bp)), then
         *    ah*2^GMP_NUMB_BITS + al = floor(ap/2^(l-2*GMP_NUMB_BITS))
         *    bh*2^GMP_NUMB_BITS + bl = floor(bp/2^(l-2*GMP_NUMB_BITS))
         *  with one of the most significant bit of ah or bh equals to 1.
         */
        static inline void
        mpn_highest_two_limbs (mp_limb_t *ah, mp_limb_t *al, mp_limb_t *bh,
                               mp_limb_t *bl, const mp_ptr ap, const mp_ptr bp,
                               mp_size_t n)
        {
            mp_limb_t mask = ap[n-1] | bp[n-1]; /* nonzero by assumption */

            if (mask & GMP_NUMB_HIGHBIT) /* if we are lucky, no shift is necessary */
            {
                *ah = ap[n-1]; *al = ap[n-2];
                *bh = bp[n-1]; *bl = bp[n-2];
            }
            else if (n == 2)
            {
                /* We use the full inputs without truncation, so we can
                  safely shift left. */
                int shift;

                count_leading_zeros (shift, mask);
                *ah = MPN_EXTRACT_NUMB (shift, ap[1], ap[0]);
                *al = ap[0] << shift;
                *bh = MPN_EXTRACT_NUMB (shift, bp[1], bp[0]);
                *bl = bp[0] << shift;
            }
            else
            {
                int shift;

                count_leading_zeros (shift, mask);
                *ah = MPN_EXTRACT_NUMB (shift, ap[n-1], ap[n-2]);
                *al = MPN_EXTRACT_NUMB (shift, ap[n-2], ap[n-3]);
                *bh = MPN_EXTRACT_NUMB (shift, bp[n-1], bp[n-2]);
                *bl = MPN_EXTRACT_NUMB (shift, bp[n-2], bp[n-3]);
            }
        }

        /*
         * Input: rp of length <= n, sp of length <= n and qp of length exactly qn.
         * Output: overwrite rp with rp+qp*sp and returns its length.
         *
         * Assumption: at least of of rp or sp must be of length n, and rp should be
         * large enough to store the result.
         *
         * Scratch variable(s): tq (must be of length at least qn + n)
         */
        static inline mp_size_t
        mpn_addmul (mp_ptr rp, mp_srcptr qp, mp_size_t qn, mp_srcptr sp,
                    mp_size_t n, mp_ptr tp)
        {
            mp_limb_t cy;
            if (qn == 1) /* common case: q has only 1 limb */
            {
                mp_limb_t q = qp[0];
                if (q == 1)
                    cy = mpn_add_n (rp, rp, sp, n);
                else
                    cy = mpn_addmul_1 (rp, sp, n, q);
            }
            else
            {
                mp_size_t spn = n;
                MPN_NORMALIZE (sp, spn);
                if (spn > 0)
                {
                    if (qn > spn)
                        mpn_mul (tp, qp, qn, sp, spn);
                    else
                        mpn_mul (tp, sp, spn, qp, qn);
                    mp_size_t tpn = spn + qn;
                    tpn -= (tp[tpn-1] == 0);

                    if (tpn >= n)
                    {
                        cy = mpn_add (rp, tp, tpn, rp, n);
                        n = tpn;
                    }
                    else /* tpn < n */
                    {
                        /* In this case, rp has exactly n limbs before the addition because
                         * qn >= 1 and tpn < n implies spn < n.
                         */
                        cy = mpn_add (rp, rp, n, tp, tpn);
                    }
                }
                else /* sp is zero => no mul, no add */
                    cy = 0;
            }
            rp[n] = cy;
            n += (cy > 0);
            return n;
        }

        /* */
        static inline void
        redcify (mp_ptr rp, mp_srcptr up, mp_size_t un, mp_srcptr mp, mp_size_t n,
                 mp_ptr tp, mp_ptr qp)
        {
            mpn_zero (tp, n);
            mpn_copyi (tp + n, up, un);
            mpn_tdiv_qr (qp, rp, 0L, tp, un + n, mp, n);
        }

    } /* anonymous namespace */

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
    class Mpz::ModInverseException : public std::invalid_argument
    {
    public:
        ModInverseException() : std::invalid_argument("not invertible") { }
    };

/* */
    inline
    Mpz::Mpz ()
    {
        mpz_init (mpz_);
    }

/* */
    inline
    Mpz::Mpz (const Mpz &v)
    {
        mpz_init_set (mpz_, v.mpz_);
    }

/* */
    inline
    Mpz::Mpz (Mpz &&v)
    {
        ALLOC(mpz_) = ALLOC (v.mpz_);
        SIZ(mpz_) = SIZ (v.mpz_);
        PTR(mpz_) = PTR (v.mpz_);

        ALLOC(v.mpz_) = 0;
        SIZ(v.mpz_) = 0;
        PTR(v.mpz_) = NULL;
    }

#if 0
    /* */
inline
Mpz::Mpz (mpz_srcptr v)
{
  mpz_init_set (mpz_, v);
}
#endif

/* */
    inline
    Mpz::Mpz (unsigned long v)
    {
        mpz_init_set_ui (mpz_, v);
    }

/* */
    inline
    Mpz::Mpz (long v)
    {
        mpz_init_set_si (mpz_, v);
    }

/* */
    inline
    Mpz::Mpz (const std::string &s)
    {
        int ret = mpz_init_set_str (mpz_, s.c_str(), 0);
        if (ret)
            throw std::runtime_error (std::string ("could not parse '") + s
                                      + std::string ("' as a valid number"));
    }

/* */
    inline
    Mpz::Mpz (mpf_srcptr v) : Mpz()
    {
        *this = v;
    }

/* */
    inline
    Mpz::Mpz (const std::vector<unsigned char> &data, size_t nb_bits) : Mpz()
    {
        /* the binary data is interpreted most significant bit first */
        mpz_import (mpz_, data.size(), 1, 1, 0, 0, data.data());
        if (nb_bits > data.size() * CHAR_BIT)
            throw std::runtime_error ("not enough data to read the number of bits");
        else
            divby2k (*this, *this, data.size() * CHAR_BIT - nb_bits);
    }

/* */
    inline
    Mpz::Mpz (const BIGNUM *v) : Mpz()
    {
        *this = v;
    }

/* */
    inline
    Mpz::~Mpz ()
    {
        mpz_clear (mpz_);
    }

/* */
    inline
    Mpz & Mpz::operator= (const Mpz &v)
    {
        mpz_set (mpz_, v.mpz_);
        return *this;
    }

/* */
    inline
    Mpz & Mpz::operator= (Mpz &&v)
    {
        mpz_swap (mpz_, v.mpz_);
        return *this;
    }

/* */
    inline
    Mpz & Mpz::operator= (mpf_srcptr v)
    {
        mpz_set_f (mpz_, v);
        return *this;
    }

/* */
    inline
    Mpz & Mpz::operator= (unsigned long v)
    {
        mpz_set_ui (mpz_, v);
        return *this;
    }

/* */
    inline
    Mpz & Mpz::operator= (long v)
    {
        mpz_set_si (mpz_, v);
        return *this;
    }

/* */
    inline
    Mpz & Mpz::operator= (const std::string &s)
    {
        int ret = mpz_set_str (mpz_, s.c_str(), 0);
        if (ret)
            throw std::runtime_error (std::string ("could not parse '") + s
                                      + std::string ("' as a valid number"));
        return *this;
    }

/* */
    inline
    Mpz & Mpz::operator= (const BIGNUM *bn)
    {
        int nbytes = BN_num_bytes (bn);
        if (nbytes > 0)
        {
            unsigned char *tmp = (unsigned char *) OPENSSL_malloc (nbytes);
            if (tmp == NULL)
                throw std::runtime_error ("could not allocate temporary buffer");

            BN_bn2lebinpad (bn, tmp, nbytes);
            mpz_import (mpz_, nbytes, -1, 1, 0, 0, tmp);

            if (BN_is_negative (bn))
                neg();

            OPENSSL_free (tmp);
        }
        else
            *this = 0UL;

        return *this;
    }

/* */
    inline
    bool Mpz::operator== (const Mpz &other) const
    {
        return richcmp (*this, other) == 0;
    }

/* */
    inline
    bool Mpz::operator!= (const Mpz &other) const
    {
        return richcmp (*this, other) != 0;
    }

/* */
    inline
    bool Mpz::operator<  (const Mpz &other) const
    {
        return richcmp (*this, other) <  0;
    }

/* */
    inline
    bool Mpz::operator>  (const Mpz &other) const
    {
        return richcmp (*this, other) >  0;
    }

/* */
    inline
    bool Mpz::operator<= (const Mpz &other) const
    {
        return richcmp (*this, other) <= 0;
    }

/* */
    inline
    bool Mpz::operator>= (const Mpz &other) const
    {
        return richcmp (*this, other) >= 0;
    }

/* */
    inline
    bool Mpz::operator== (unsigned long v) const
    {
        return richcmp (*this, v) == 0;
    }

/* */
    inline
    bool Mpz::operator!= (unsigned long v) const
    {
        return richcmp (*this, v) != 0;
    }

/* */
    inline
    bool Mpz::operator<  (unsigned long v) const
    {
        return richcmp (*this, v) <  0;
    }

/* */
    inline
    bool Mpz::operator>  (unsigned long v) const
    {
        return richcmp (*this, v) >  0;
    }

/* */
    inline
    bool Mpz::operator<= (unsigned long v) const
    {
        return richcmp (*this, v) <= 0;
    }

/* */
    inline
    bool Mpz::operator>= (unsigned long v) const
    {
        return richcmp (*this, v) >= 0;
    }

/* */
    inline
    bool Mpz::operator== (long v) const
    {
        return richcmp (*this, v) == 0;
    }

/* */
    inline
    bool Mpz::operator!= (long v) const
    {
        return richcmp (*this, v) != 0;
    }

/* */
    inline
    bool Mpz::operator<  (long v) const
    {
        return richcmp (*this, v) <  0;
    }

/* */
    inline
    bool Mpz::operator>  (long v) const
    {
        return richcmp (*this, v) >  0;
    }

/* */
    inline
    bool Mpz::operator<= (long v) const
    {
        return richcmp (*this, v) <= 0;
    }

/* */
    inline
    bool Mpz::operator>= (long v) const
    {
        return richcmp (*this, v) >= 0;
    }

/* */
    inline
    Mpz::operator mpz_srcptr() const
    {
        return mpz_;
    }

/* */
    inline
    Mpz::operator unsigned long () const
    {
        if (!mpz_fits_uint_p (mpz_))
            throw std::runtime_error ("mpz value could not be parsed as an unsigned long");
        else
            return mpz_get_ui (mpz_);
    }

/* */
    inline
    Mpz::operator long () const
    {
        if (!mpz_fits_sint_p (mpz_))
            throw std::runtime_error ("mpz value could not be parsed as an long");
        else
            return mpz_get_si (mpz_);
    }

/* */
    inline
    size_t Mpz::nbits () const
    {
        return mpz_sizeinbase (mpz_, 2);
    }

/* */
    inline
    size_t Mpz::ndigits () const
    {
        return mpz_sizeinbase (mpz_, 10);
    }

/* */
    inline
    size_t Mpz::nlimbs () const
    {
        return mpz_size (mpz_);
    }

/* */
    inline
    int Mpz::sgn () const
    {
        return mpz_sgn (mpz_);
    }

    inline
    std::string Mpz::str_value() const {
        return mpz_get_str(NULL, 10, mpz_);
    }

/* */
    inline
    bool Mpz::is_zero () const
    {
        return sgn() == 0;
    }

/* */
    inline
    bool Mpz::is_odd () const
    {
        return mpz_odd_p (mpz_);
    }

/* */
    inline
    bool Mpz::is_even () const
    {
        return mpz_even_p (mpz_);
    }

/* */
    inline
    bool Mpz::is_one () const
    {
        return mpz_cmp_ui (mpz_, 1UL) == 0;
    }

/*
 * Return 1 if n is prime (or probably prime), return 0 otherwise.
 */
    inline
    bool Mpz::is_prime (int reps) const
    {
        int r = mpz_probab_prime_p (mpz_, reps);
        return (r > 0);
    }

/* */
    inline
    bool Mpz::is_divisible_by (const Mpz &d) const
    {
        return mpz_divisible_p (mpz_, d.mpz_);
    }

/* */
    inline
    void Mpz::neg ()
    {
        SIZ(mpz_) = -SIZ(mpz_);
    }

/*
 * Return integer with bits from index to index-len+1 (inclusive)
 * Assumes len is positive and less than GMP_LIMB_BITS (i.e., 32 or 64)
 * The sign is not taken into account.
 */
    inline
    mp_limb_t Mpz::extract_bits (size_t index, size_t len) const
    {
        mp_limb_t r;
        const mp_limb_t mask = ((1UL << len)-1UL);
        const size_t limb_high = mpz_getlimbn (mpz_, index/GMP_NUMB_BITS);
        const size_t im = index % GMP_NUMB_BITS;

        if (len <= im+1) /* all bits are in limb_high */
        {
            r = limb_high >> (im-len+1);
        }
        else
        {
            const size_t limb_low = len > index+1 ? 0 :
                                    mpz_getlimbn (mpz_, (index - len + 1)/GMP_NUMB_BITS);
            r = (limb_high << (len-im-1)) | (limb_low >> (im+1+GMP_NUMB_BITS-len));
        }

        return r & mask;
    }

/* */
    inline
    int Mpz::tstbit (size_t i) const
    {
        return mpz_tstbit (mpz_, i);
    }

/* */
    inline
    void Mpz::setbit (size_t i)
    {
        mpz_setbit (mpz_, i);
    }

/* */
    inline
    unsigned long Mpz::mod4 () const
    {
        unsigned long r = mpz_get_ui (mpz_);
        return (sgn() < 0 ? -r : r) & 0x3UL;
    }

/* */
    inline
    unsigned long Mpz::mod8 () const
    {
        unsigned long r = mpz_get_ui (mpz_);
        return (sgn() < 0 ? -r : r) & 0x7UL;
    }

/* */
    inline
    size_t Mpz::val2 () const
    {
        return sgn() == 0 ? SIZE_MAX : mpn_scan1 (mpz_->_mp_d, 0);
    }

/* */
    inline
    void Mpz::nextprime ()
    {
        mpz_nextprime (mpz_, mpz_);
    }

/* */
    inline
    int Mpz::legendre (const Mpz &l) const
    {
        return mpz_legendre (mpz_, l.mpz_);
    }

/* */
    inline
    int Mpz::jacobi (const Mpz &l) const
    {
        return mpz_jacobi (mpz_, l.mpz_);
    }

/* */
    inline
    int Mpz::kronecker (const Mpz &l) const
    {
        return mpz_kronecker (mpz_, l.mpz_);
    }

/* */
    inline
    void Mpz::swap (Mpz &op1, Mpz &op2)
    {
        mpz_swap (op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::abs (Mpz &r, const Mpz &op)
    {
        mpz_abs (r.mpz_, op.mpz_);
    }

/* */
    inline
    int Mpz::cmpabs (const Mpz &a, const Mpz &b)
    {
        return mpz_cmpabs (a.mpz_, b.mpz_);
    }

/* */
    inline
    void Mpz::add (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_add (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::add (Mpz &r, const Mpz &op1, unsigned long op2)
    {
        mpz_add_ui (r.mpz_, op1.mpz_, op2);
    }

/* */
    inline
    void Mpz::sub (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_sub (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::sub (Mpz &r, const Mpz &op1, unsigned long op2)
    {
        mpz_sub_ui (r.mpz_, op1.mpz_, op2);
    }

/* */
    inline
    void Mpz::mul (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_mul (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::mul (Mpz &r, const Mpz &op1, unsigned long op2)
    {
        mpz_mul_ui (r.mpz_, op1.mpz_, op2);
    }

/* */
    inline
    void Mpz::mulby2k (Mpz &r, const Mpz &op, mp_bitcnt_t k)
    {
        mpz_mul_2exp (r.mpz_, op.mpz_, k);
    }

/* */
    inline
    void Mpz::mulby2k (Mpz &r, unsigned long op, mp_bitcnt_t k)
    {
        r = op;
        mulby2k (r, r, k);
    }

/* */
    inline
    void Mpz::mulby2 (Mpz &r, const Mpz &op)
    {
        mulby2k (r, op, 1); /* maybe an add is faster ?? */
    }

/* */
    inline
    void Mpz::mulby4 (Mpz &r, const Mpz &op)
    {
        mulby2k (r, op, 2);
    }

/* */
    inline
    void Mpz::addmul (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_addmul (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::submul (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_submul (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::divby2k (Mpz &r, const Mpz &op, mp_bitcnt_t k)
    {
        mpz_fdiv_q_2exp (r.mpz_, op.mpz_, k);
    }

/* */
    inline
    void Mpz::divby2 (Mpz &r, const Mpz &op)
    {
        divby2k (r, op, 1);
    }

/* */
    inline
    void Mpz::divby4 (Mpz &r, const Mpz &op)
    {
        divby2k (r, op, 2);
    }

/* */
    inline
    void Mpz::divexact (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_divexact (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::divexact (Mpz &r, const Mpz &op1, unsigned long op2)
    {
        mpz_divexact_ui (r.mpz_, op1.mpz_, op2);
    }

/* */
    inline
    void Mpz::cdiv_qr (Mpz &q, Mpz &r, const Mpz &n, const Mpz &d)
    {
        mpz_cdiv_qr (q.mpz_, r.mpz_, n.mpz_, d.mpz_);
    }

/* */
    inline
    void Mpz::fdiv_qr (Mpz &q, Mpz &r, const Mpz &n, const Mpz &d)
    {
        mpz_fdiv_qr (q.mpz_, r.mpz_, n.mpz_, d.mpz_);
    }

/* */
    inline
    void Mpz::mod (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        mpz_mod (r.mpz_, op1.mpz_, op2.mpz_);
    }

/* */
    inline
    void Mpz::mod2k (Mpz &r, const Mpz &op, mp_bitcnt_t k)
    {
        mpz_fdiv_r_2exp (r.mpz_, op.mpz_, k);
    }

/* */
    inline
    void Mpz::mod2k_centered (Mpz &r, const Mpz &op, mp_bitcnt_t k)
    {
        Mpz::mod2k (r, op, k);

        /* substract 2^k if needed */
        if (r.tstbit (k-1))
        {
            mpn_com (r.mpz_->_mp_d, r.mpz_->_mp_d, r.mpz_->_mp_size);
            Mpz::add (r, r, 1UL);
            Mpz::mod2k (r, r, k);
            r.neg();
        }
    }

/* */
    inline
    void Mpz::mod_inverse (Mpz &r, const Mpz &op1, const Mpz &op2)
    {
        int ret = mpz_invert (r.mpz_, op1.mpz_, op2.mpz_);
        if (ret == 0)
            throw ModInverseException ();
    }

/*
 * Input: op1 and k
 *
 * Output: set r to op1^-1 modulo 2^k
 *
 * Assumption:
 *    - op1 is odd
 *    - k >= 1
 *    - r and op1 are different variables
 *
 * Scratch variable(s): t
 */
    inline
    void Mpz::mod_inverse_2k (Mpz &r, const Mpz &op1, mp_bitcnt_t k, Mpz &t)
    {
        if (op1.is_even())
            throw ModInverseException ();
        r = 1UL;
        for (size_t i = 1; i < k; i <<= 1)
        {
            t = 2UL;
            Mpz::submul (t, r, op1);
            Mpz::mul (t, r, t);
            Mpz::mod2k (r, t, i << 1);
        }
    }

    inline
    void Mpz::pow (Mpz &res, const Mpz &b, unsigned long int e) {
        mpz_pow_ui (res.mpz_, b.mpz_, e);
    }

/* */
    inline
    void Mpz::pow_mod (Mpz &r, const Mpz &b, const Mpz &e, const Mpz &m)
    {
        mpz_powm (r.mpz_, b.mpz_, e.mpz_, m.mpz_);
    }

/*
 * Multiple exponentiation.
 *
 * Input:
 *  - f: positive integer (the base)
 *  - n: integer (the exponent)
 *  - m: positive integer (the modulus)
 *  - e: a positive integer
 *  - fe: positive integer such that fe = f^(2^e) mod m
 *  - f2e: positive integer such that fe = f^(2^2e) mod m
 *  - f3e: positive integer such that fe = f^(2^3e) mod m
 * Ouput:
 *  - r: output integer corresponding to f^n mod m.
 *
 * Assumption: the modulus m is odd
 *
 */
    inline
    void Mpz::pow_mod (Mpz &r, const Mpz &f, const Mpz &n, const Mpz &m, size_t e,
                       const Mpz &fe, const Mpz &f2e, const Mpz &f3e)
    {
        if (n.is_zero ())
        {
            r = 1UL;
        }
        else if (n.nbits() < e)
        {
            pow_mod (r, f, n, m);
        }
        else /* n != 0: exponentiation with abs(n) and handle sign after */
        {
            /* */
            mp_srcptr mp = PTR (m.mpz_);
            mp_size_t nlimbs = ABSIZ(m.mpz_);
            mp_size_t itch = mpn_binvert_itch (nlimbs);
            if (itch < 2*nlimbs)
                itch = 2*nlimbs;

            Mpz mi, T0, T1;
            mp_ptr mip = mpz_limbs_write (mi.mpz_, nlimbs);
            mp_ptr t0 = mpz_limbs_write (T0.mpz_, itch);
            mp_ptr t1 = mpz_limbs_write (T1.mpz_, nlimbs+1);

            mpn_binvert (mip, mp, nlimbs, t0);

#define SQR_REDC(r, a) do {                           \
    mpn_sqr (t0, PTR((a).mpz_), nlimbs);              \
    mpn_redc_n (PTR((r).mpz_), t0, mp, nlimbs, mip);  \
  } while (0)
#define MUL_REDC(r, a, b) do {                            \
    mpn_mul_n (t0, PTR((a).mpz_), PTR((b).mpz_), nlimbs); \
    mpn_redc_n (PTR((r).mpz_), t0, mp, nlimbs, mip);      \
  } while (0)

            /* precomputations */
            /* tab[i] = f^b0 * fe^b1 * f2e^b2 * f3e^b3
             * where [ b0, b1, b2, b3] is (i+1) written in basis 2.
             */
            Mpz tab[15];

            for (size_t i = 0; i < 15; i++)
            {
                _mpz_realloc (tab[i].mpz_, nlimbs);
            }

            redcify (PTR(tab[0].mpz_), PTR(f.mpz_), f.nlimbs(), mp, nlimbs, t0, t1);
            redcify (PTR(tab[1].mpz_), PTR(fe.mpz_), fe.nlimbs(), mp, nlimbs, t0, t1);
            redcify (PTR(tab[3].mpz_), PTR(f2e.mpz_), f2e.nlimbs(), mp, nlimbs, t0, t1);
            redcify (PTR(tab[7].mpz_), PTR(f3e.mpz_), f3e.nlimbs(), mp, nlimbs, t0, t1);

            MUL_REDC (tab[2], tab[1], tab[0]);

            for (size_t i = 0; i < 3; i++)
                MUL_REDC (tab[4+i], tab[3], tab[i]);

            for (size_t i = 0; i < 7; i++)
                MUL_REDC (tab[8+i], tab[7], tab[i]);

            /* */
            mp_ptr rp = mpz_limbs_write (r.mpz_, nlimbs);
            rp[0] = 1UL;
            redcify (rp, rp, 1, mp, nlimbs, t0, t1);

            for (size_t j = n.nbits(); j > 4*e; j--)
            {
                int b = n.tstbit (j-1);
                SQR_REDC (r, r);
                if (b)
                    MUL_REDC (r, r, tab[7]);
            }

            for (size_t j = e; j > 0; j--)
            {
                int b0 = n.tstbit (j-1);
                int b1 = n.tstbit (j-1+e);
                int b2 = n.tstbit (j-1+2*e);
                int b3 = n.tstbit (j-1+3*e);
                int idx = (b3 << 3) | (b2 << 2) | (b1 << 1) | b0;

                SQR_REDC (r, r);
                if (idx)
                    MUL_REDC (r, r, tab[idx-1]);
            }

#undef SQR_REDC
#undef MUL_REDC

            mpn_copyi (t0, rp, nlimbs);
            mpn_zero (t0 + nlimbs, nlimbs);
            mpn_redc_n (rp, t0, mp, nlimbs, mip);
            SIZ(r.mpz_) = nlimbs;
            MPN_NORMALIZE (rp, SIZ(r.mpz_));
        }
    }

/* */
    inline
    void Mpz::gcd (Mpz &g, const Mpz &a, const Mpz &b)
    {
        mpz_gcd (g.mpz_, a.mpz_, b.mpz_);
    }

/* */
    inline
    void Mpz::gcdext (Mpz &g, Mpz &u, Mpz &v, const Mpz &a, const Mpz &b)
    {
        mpz_gcdext (g.mpz_, u.mpz_, v.mpz_, a.mpz_, b.mpz_);
    }

/* */
    inline
    void Mpz::lcm (Mpz &g, const Mpz &a, const Mpz &b)
    {
        mpz_lcm (g.mpz_, a.mpz_, b.mpz_);
    }

/* */
    inline
    void Mpz::sqrt (Mpz &r, const Mpz &op)
    {
        mpz_sqrt (r.mpz_, op.mpz_);
    }

/* */
    inline
    void Mpz::root4th (Mpz &r, const Mpz &op)
    {
        mpz_root (r.mpz_, op.mpz_, 4);
    }

/*
 * Set r to a square root of s modulo l, i.e., r^2 = s mod l
 *
 * Implementation of Tonelli-Shanks algorithm.
 * Doc: https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
 */
    inline
    void Mpz::sqrt_mod_prime (Mpz &r, const Mpz &s, const Mpz &l)
    {
        Mpz Q, z, c, t, b, tmp;
        size_t M;

        sub (Q, l, 1UL);
        for (M = 0; Q.is_even(); M++, divby2 (Q, Q));
        /* Now Q*2^M = l-1 */

        for (z = 1UL; z.kronecker (l) != -1; add (z, z, 1UL));
        /* z is a non-quadratic residue */

        pow_mod (c, z, Q, l);
        pow_mod (t, s, Q, l);
        add (tmp, Q, 1UL);
        divby2 (tmp, tmp);
        pow_mod (r, s, tmp, l);

        while (!t.is_zero() && t != 1UL)
        {
            size_t i;
            tmp = t;

            for (i = 0; tmp != 1UL; i++, mul (tmp, tmp, tmp), mod (tmp, tmp, l));

            tmp = 1UL;
            mulby2k (tmp, tmp, M-i-1);
            pow_mod (b, c, tmp, l);

            M = i;
            mul (c, b, b); mod (c, c, l); /* c <- b^2 mod l */
            mul (t, t, c); mod (t, t, l); /* t <- t*c mod l = t*b^2 mod l */
            mul (r, r, b); mod (r, r, l); /* r <- r*b mod l */
        }

        if (t.is_zero())
            r = 0UL;
    }

/* */
    inline
    size_t Mpz::remove (Mpz &r, const Mpz &n, const Mpz &f)
    {
        return mpz_remove (r.mpz_, n.mpz_, f.mpz_);
    }

/* */
    inline
    void Mpz::CRT (Mpz &r, const Mpz &a1, const Mpz &m1, const Mpz &a2,
                   const Mpz &m2)
    {
        Mpz n1, n2, g, tmp;
        Mpz::gcdext (g, n1, n2, m1, m2);
        Mpz::mul (r, m2, n2);
        Mpz::mul (r, r, a1);
        Mpz::mul (tmp, m1, n1);
        Mpz::addmul (r, tmp, a2);
        if (g == 1UL)
        {
            Mpz::mul (tmp, m1, m2);
            Mpz::mod (r, r, tmp);
        }
        else
        {
            // TODO check n1 == n2 modulo g
            Mpz::divexact (r, r, g);
            Mpz::mul (tmp, m1, m2);
            Mpz::divexact (tmp, tmp, g);
            Mpz::mod (r, r, tmp);
        }
    }

/*
 * Set r to ceil(log(|n|)^2).
 *
 * Naive implementation: use Taylor expansion of log(1-z)^2
 *      log(1-z)^2 = sum_{i=1}^{infinity}{2*Hi/(i+1) * z^(i+1)}
 *  with Hi = sum_{j=1}^{i}{1/j}
 * Argument reduction from |n| to a value z in ]0, 2[ by taking square root.
 *
 * FIXME: what precision is needed ? Do we only need 2*log2(nbits) of
 * precision (+epsilon) ?
 */
    inline
    void Mpz::ceil_abslog_square (Mpz &r, const Mpz &n)
    {
        const size_t nbits = n.nbits();
        size_t m;

        mpf_t nf, acc, z, pow, H, t, tmp;
        mpf_init2 (nf, nbits);
        mpf_init2 (acc, nbits);
        mpf_init2 (z, nbits);
        mpf_init2 (pow, nbits);
        mpf_init2 (H, nbits);
        mpf_init2 (t, nbits);
        mpf_init2 (tmp, nbits);

        mpf_set_z (nf, n.mpz_);
        mpf_abs (nf, nf);

        /* compute nf and m such that log(|n|)^2 = 4^m*log(nf)^2 with 0<nf<2 */
        m = 0;
        for (m = 0; mpf_cmp_ui (nf, 2) >= 0; m += 1)
        {
            mpf_sqrt (nf, nf);
        }

        mpf_ui_sub (z, 1, nf); /* -1 < z < 1 */
        mpf_mul (pow, z, z);
        mpf_set_ui (acc, 0);
        mpf_set_ui (H, 1);

        for (size_t i = 1; i < 1000000; i++) /* 1e6 harcoded max iter */
        {
            mpf_set_ui (tmp, i+1);
            mpf_ui_div (tmp, 1, tmp);
            mpf_mul (t, pow, H);
            mpf_mul_2exp (t, t, 1);
            mpf_mul (t, t, tmp);
            mpf_add (acc, acc, t);

            mpf_mul (pow, pow, z);
            mpf_add (H, H, tmp);

            mpf_div (tmp, t, acc);
            mpf_abs (tmp, tmp);
            if (mpf_cmp_d (tmp, 1e-9) <= 0) /* TODO: remove hardcoded constant */
                break;
        }

        mpf_mul_2exp (acc, acc, 2*m); /* mul by 2^(2*m) = 4^m */
        mpf_ceil (acc, acc);
        mpz_set_f (r.mpz_, acc);

        mpf_clears (nf, acc, z, pow, H, t, tmp, NULL);
    }

/*
 * Input: a, b and target_nlimb
 *
 * output: a and b of length <= target_nlimb and matrix U = (uij)
 *  (0 <= i,j < 2)
 * such that:
 *  - U*(a, b) = (a_input, b_input)
 *  - det U = 1
 *
 * Note: input a and b are overwritten with the output values
 *
 * Assumption: target_nlimb must be >= 1.
 *
 * Scratch variable(s): t0, t1
 */
    inline
    void Mpz::partial_euclid (Mpz &u00, Mpz &u01, Mpz &u10, Mpz &u11, Mpz &a,
                              Mpz &b, mp_size_t target_nlimb, Mpz &t0, Mpz &t1)
    {
        int swapped = 0;

        /* ensure that ABSIZ(b) >= ABSIZ (a) */
        if (ABSIZ (b.mpz_) < ABSIZ (a.mpz_))
        {
            swap (a, b);
            swapped = 1;
        }

        /* signs are handled before swap is undone (if necessary) */
        int a_is_neg = SIZ (a.mpz_) < 0;
        int b_is_neg = SIZ (b.mpz_) < 0;

        if (SIZ (a.mpz_) == 0) /* if a == 0 => identity matrix */
        {
            u00 = 1UL; u01 = 0UL;
            u10 = 0UL; u11 = 1UL;
        }
        else
        {
            mp_size_t n = ABSIZ (b.mpz_); /* Fact: 0 < ABSIZ(a) <= ABSIZ(b) = n */

            /* get the pointer for a and b (and reallocate a if necessary) */
            mp_ptr const ap = mpz_limbs_modify (a.mpz_, n);
            mp_ptr const bp = mpz_limbs_modify (b.mpz_, n);
            mpn_zero (ap+ABSIZ(a.mpz_), n-ABSIZ(a.mpz_));

            /* realloc u10, u11 if necessary, and set u10 to 0 and u11 to 1 */
            mp_ptr const u10p = mpz_limbs_write (u10.mpz_, n+1);
            mp_ptr const u11p = mpz_limbs_write (u11.mpz_, n+1);
            mpn_zero (u10p, n+1);
            mpn_zero (u11p, n+1);
            u11p[0] = 1;
            mp_size_t un = 1;

            /* realloc u00, u01 if necessary, and set u00 to 1 and u01 to 0 */
            mp_ptr const u00p = mpz_limbs_write (u00.mpz_, n+1);
            mp_ptr const u01p = mpz_limbs_write (u01.mpz_, n+1);
            mpn_zero (u00p, n+1);
            mpn_zero (u01p, n+1);
            u00p[0] = 1;
            mp_size_t vn = 1;

            /* get the pointer for t0 and t1 (and reallocate a if necessary) */
            mp_ptr const t0p = mpz_limbs_modify (t0.mpz_, n+1);
            mp_ptr const t1p = mpz_limbs_modify (t1.mpz_, n+1);
            mpn_zero (t0p, n+1);
            mpn_zero (t1p, n+1);

            /* Loop invariant: n == ABSIZ(b) or ABSIZ(a), and both are <= n */
            while (n > target_nlimb)
            {
                hgcd_matrix1 M;
                mp_limb_t ah, al, bh, bl;

                mpn_highest_two_limbs (&ah, &al, &bh, &bl, ap, bp, n);

                /* Try an mpn_hgcd2 step */
                if (mpn_hgcd2 (ah, al, bh, bl, &M))
                {
                    /* Compute  M^-1 * (a,b), the result is written in (t1p, bp) then
                     * swap to obtain it in (ap ,bp).
                     * n is updated to the new max (ABSIZ(a), ABSIZ(b))
                     */
                    n = mpn_matrix22_mul1_inverse_vector (&M, t1p, ap, bp, n);
                    mpn_copyi (ap, t1p, n);
                    //MP_PTR_SWAP (ap, t1p);

                    /* apply (u10,u11) * M, the result is written in (t0p, u11) then
                     * swap to obtain it in (u10 ,u11).
                     * un is updated to the new max (ABSIZ(u10), ABSIZ(u11))
                     */
                    un = mpn_hgcd_mul_matrix1_vector(&M, t0p, u10p, u11p, un);
                    mpn_copyi (u10p, t0p, un);
                    //MP_PTR_SWAP (u10, t0p);

                    /* same for u00 and u01 */
                    vn = mpn_hgcd_mul_matrix1_vector(&M, t0p, u00p, u01p, vn);
                    mpn_copyi (u00p, t0p, vn);
                }
                else
                {
                    /* Looking at the code of mpn_hgcd2, it returns 0 in 3 cases:
                     *  1. if ah < 2 or bh < 2: as the most significant bit of ah or bh
                     *      must be 1, it means that the ratio a/b is too large
                     *  2. (al|ah) >= (bl|bh) and highest limb of (al|ah)-(bl|bh) is < 2
                     *  3. (bl|bh) >= (al|ah) and highest limb of (bl|bh)-(al|ah) is < 2
                     * For case 1, we perform a div, for 2 and 3 we perform a sub.
                     */
                    if (bh < 2) /* a is too large compared to b */
                    {
                        /* do (a, b) <- (a-b*q, b) */
                        mp_size_t bn = n - 1;
                        MPN_NORMALIZE (bp, bn);
                        mpn_tdiv_qr (t1p, ap, 0, ap, n, bp, bn);
                        mp_size_t qn = n - bn + 1;
                        MPN_NORMALIZE (t1p, qn);
                        n = bn;

                        vn = mpn_addmul (u01p, t1p, qn, u00p, vn, t0p);
                        un = mpn_addmul (u11p, t1p, qn, u10p, un, t0p);
                    }
                    else if (ah < 2) /* b is too large compared to a */
                    {
                        /* do (a, b) <- (a, b-a*q) */
                        mp_size_t an = n - 1;
                        MPN_NORMALIZE (ap, an);
                        mpn_tdiv_qr (t1p, bp, 0, bp, n, ap, an);
                        mp_size_t qn = n - an + 1;
                        MPN_NORMALIZE (t1p, qn);
                        n = an;

                        vn = mpn_addmul (u00p, t1p, qn, u01p, vn, t0p);
                        un = mpn_addmul (u10p, t1p, qn, u11p, un, t0p);
                    }
                    else /* a and b are too close */
                    {
                        int c = mpn_cmp (ap, bp, n);
                        if (c < 0)
                        {
                            /* do (a, b) <- (a, b-a) */
                            mpn_sub_n (bp, bp, ap, n);

                            u00p[vn] = mpn_add_n (u00p, u00p, u01p, vn);
                            vn += (u00p[vn] > 0);
                            u10p[un] = mpn_add_n (u10p, u10p, u11p, un);
                            un += (u10p[un] > 0);
                        }
                        else
                        {
                            /* do (a, b) <- (a-b, b) */
                            mpn_sub_n (ap, ap, bp, n);

                            u01p[vn] = mpn_add_n (u01p, u00p, u01p, vn);
                            vn += (u01p[vn] > 0);
                            u11p[un] = mpn_add_n (u11p, u10p, u11p, un);
                            un += (u11p[un] > 0);
                        }
                    }
                }
            }
            /* Note that sign is handled before reswapping a and b, if necessary */
            mpz_limbs_finish (a.mpz_, a_is_neg ? -n : n);
            mpz_limbs_finish (b.mpz_, b_is_neg ? -n : n);
            mpz_limbs_finish (u10.mpz_, b_is_neg ^ a_is_neg ? -un : un);
            mpz_limbs_finish (u11.mpz_, un);
            mpz_limbs_finish (u00.mpz_, vn);
            mpz_limbs_finish (u01.mpz_, b_is_neg ^ a_is_neg ? -vn : vn);
        }

        if (swapped)
        {
            /* swap a and b, and the two diagonal of the matrix */
            swap (u10, u01);
            swap (u11, u00);
            swap (a, b);
        }
    }

/* */
    inline
    void Mpz::partial_euclid (Mpz &u00, Mpz &u01, Mpz &u10, Mpz &u11, Mpz &a,
                              Mpz &b, mp_size_t target_nlimb)
    {
        Mpz t0, t1;
        partial_euclid (u00, u01, u10, u11, a, b, target_nlimb, t0, t1);
    }

/* */
    std::ostream & operator<< (std::ostream &o, const Mpz &v)
    {
        return o << v.mpz_;
    }

/* */
    std::istream & operator>> (std::istream &i, Mpz &v)
    {
        return i >> v.mpz_;
    }

/* */
    inline
    int Mpz::richcmp (const Mpz &a, const Mpz &b)
    {
        return mpz_cmp (a.mpz_, b.mpz_);
    }

/* */
    inline
    int Mpz::richcmp (const Mpz &a, unsigned long v)
    {
        return mpz_cmp_ui (a.mpz_, v);
    }

/* */
    inline
    int Mpz::richcmp (const Mpz &a, long v)
    {
        return mpz_cmp_si (a.mpz_, v);
    }

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/* */
    inline
    RandGen::RandGen ()
    {
        gmp_randinit_default (rand_);
    }

/* */
    inline
    RandGen::RandGen (const RandGen &other)
    {
        gmp_randinit_set (rand_, other.rand_);
    }

/* */
    inline
    RandGen::RandGen (const Mpz &seed) : RandGen()
    {
        set_seed (seed);
    }

/* */
    inline
    RandGen::~RandGen ()
    {
        gmp_randclear (rand_);
    }

/* */
    inline void
    RandGen::set_seed (const Mpz &seed)
    {
        gmp_randseed (rand_, seed.mpz_);
    }

/* */
    inline
    Mpz RandGen::random_mpz (const Mpz &m)
    {
        Mpz r;
        mpz_urandomm (r.mpz_, rand_, m.mpz_);
        return r;
    }

/* */
    inline
    Mpz RandGen::random_mpz_2exp (mp_bitcnt_t n)
    {
        Mpz r;
        mpz_urandomb (r.mpz_, rand_, n);
        return r;
    }

/* */
    inline
    unsigned char RandGen::random_uchar ()
    {
        return gmp_urandomb_ui (rand_, CHAR_BIT);
    }

/* */
    inline
    unsigned long RandGen::random_ui (unsigned long m)
    {
        return gmp_urandomm_ui (rand_, m);
    }

/* */
    inline
    unsigned long RandGen::random_ui_2exp (mp_bitcnt_t n)
    {
        return gmp_urandomb_ui (rand_, n);
    }

/* */
    inline
    Mpz RandGen::random_negative_discriminant (mp_bitcnt_t n)
    {
        Mpz D;
        unsigned long Dmod4;
        do
        {
            D = random_mpz_2exp (n);
            D.neg();
            Dmod4 = D.mod4();
        } while (Dmod4 == 2 || Dmod4 == 3);
        return D;
    }

/* */
    inline
    bool RandGen::random_bool ()
    {
        return static_cast<bool>(random_ui_2exp (1));
    }

/*
 * Return a random prime with exactly nbits bits, i.e., a prime p such that
 *      2^(nbits-1) <= p < 2^nbits
 * If nbits <= 1, it always returns 2.
 */
    inline
    Mpz RandGen::random_prime (size_t nbits)
    {
        Mpz p;

        if (nbits <= 1)
            p = 2UL;
        else if (nbits == 2)
            p = random_bool () ? 3UL : 2UL;
        else
        {
            do {
                mpz_urandomb (p.mpz_, rand_, nbits); /* random 0 <= p < 2^nbits */
                p.setbit (nbits-1);                 /* ensure that p is >= 2^(nbits-1) */
                p.nextprime ();                     /* ensure p is prime */
            } while (p.nbits() != nbits);
        }

        return p;
    }

/******************************************************************************/
/******************************************************************************/
/******************************************************************************/
/* */
    inline
    JSF::JSF (const Mpz &n0, const Mpz &n1)
            : std::vector<uint8_t> (std::max (n0.nbits(), n1.nbits()) + 1)
    {
        int d0 = 0, d1 = 0;
        int n0j = n0.tstbit (0);
        int n0jp1 = n0.tstbit (1);
        int n0jp2 = n0.tstbit (2);
        int n1j = n1.tstbit (0);
        int n1jp1 = n1.tstbit (1);
        int n1jp2 = n1.tstbit (2);

        for (size_t j = 0; j < size(); j++)
        {
            int u0, u1;

            /* bi := (di + 2*nijp1 + nij) % 4 == 2.
             * Computed now, as di may change when we need this test.
             */
            int b0 = d0 == n0j && n0jp1 ^ d0;
            int b1 = d1 == n1j && n1jp1 ^ d1;

            if (d0 == n0j)
                u0 = 0;
            else
            {
                u0 = n0jp1 ^ ((n0jp2 ^ n0jp1) & b1) ? 3 : 1;
                d0 = u0 >> 1;
            }

            if (d1 == n1j)
                u1 = 0;
            else
            {
                u1 = n1jp1 ^ ((n1jp2 ^ n1jp1) & b0) ? 3 : 1;
                d1 = u1 >> 1;
            }

            set (j, u0, u1);

            n0j = n0jp1; n0jp1 = n0jp2; n0jp2 = n0.tstbit (j+3);
            n1j = n1jp1; n1jp1 = n1jp2; n1jp2 = n1.tstbit (j+3);
        }

        if (operator[] (size()-1) == 0)
            resize (size()-1);
    }

/* */
    inline
    uint8_t JSF::operator[] (size_t i) const
    {
        if (i < size())
            return std::vector<uint8_t>::operator[] (i);
        else
            return 0U;
    }

/* */
    inline
    void JSF::set (size_t i, int d0, int d1)
    {
        std::vector<uint8_t>::operator[] (i) = (d1 << 4) | d0;
    }

#undef ALLOC
#undef PTR
#undef SIZ
#undef ABS
#undef ABSIZ
#undef MPN_NORMALIZE
#undef GMP_NUMB_HIGHBIT
#undef MPN_EXTRACT_NUMB
#undef count_leading_zeros

#undef mpn_hgcd2
#undef mpn_matrix22_mul1_inverse_vector
#undef mpn_hgcd_mul_matrix1_vector
#undef mpn_binvert
#undef mpn_binvert_itch
#undef mpn_redc_n

}

//#include "bicycl/seclevel.hpp"
namespace BICYCL
{
    /*****/
    class InvalidSecLevelException : public std::invalid_argument
    {
    public:
        InvalidSecLevelException() : std::invalid_argument("not a valid SecLevel")
        {
        }
    };

    /*****/
    class SecLevel
    {
    public:
        enum Value : unsigned int
        {
            _112 = 112,
            _128 = 128,
            _192 = 192,
            _256 = 256,
        };

        static const std::vector<SecLevel> All ();

        SecLevel() = delete;
        constexpr SecLevel (Value seclevel) : value_(seclevel) { }
        explicit SecLevel (unsigned int s);
        explicit SecLevel (const std::string &s);

        /* Allow switch, comparisons and usage as key std::map */
        constexpr operator Value() const { return value_; }

        /* */
        explicit operator bool() = delete;

        /* */
        size_t RSA_modulus_bitsize () const;
        size_t discriminant_bitsize () const;
        int elliptic_curve_openssl_nid () const;
        int sha3_openssl_nid () const;

        /* */
        friend std::ostream & operator<< (std::ostream &o, SecLevel seclevel);
        friend std::string to_string (SecLevel seclevel);

    protected:
        Value value_;
    };
}

//#include "bicycl/openssl_wrapper.hpp"
namespace BICYCL
{
    namespace OpenSSL
    {
        /*****/
        void random_bytes (unsigned char *buf, int num);

        /*****/
        class HashAlgo
        {
        public:
            using Digest = std::vector<unsigned char>;

            static const int SHAKE128 = NID_shake128;
            static const int SHA3_224 = NID_sha3_224;
            static const int SHA3_256 = NID_sha3_256;
            static const int SHA3_384 = NID_sha3_384;
            static const int SHA3_512 = NID_sha3_512;

            /* constructors */
            HashAlgo (SecLevel seclevel); /* Use SHA3 with desired security level */
            HashAlgo (int nid);
            HashAlgo (const HashAlgo &H);
            HashAlgo (HashAlgo &&H);

            /* destructor */
            ~HashAlgo ();

            /* assignment */
            HashAlgo & operator= (const HashAlgo &H);
            HashAlgo & operator= (HashAlgo &&H);

            /* getters */
            int digest_size () const;

            template <typename First, typename... Rem>
            Digest operator() (const First &first, const Rem&... rem);

        protected:
            template <typename First, typename... Rem>
            void hash_update (const First & first, const Rem&... rem);

            void hash_update_implem (const void *ptr, size_t n);

        private:
            static EVP_MD_CTX * new_ctx_ ();

            const EVP_MD *md_;
            EVP_MD_CTX *mdctx_;
        };

        /*****/
        class ECGroup; /* forward declaration */

        /*****/
        class BN
        {
            friend ECGroup;

        public:
            using RawSrcPtr = const BIGNUM *;

            /* constructors */
            BN ();
            BN (const BN &other);
            BN (BN &&other);

            /* destructor */
            ~BN ();

            /* assignment */
            BN & operator= (const BN &other);
            BN & operator= (BN &&other);

            /* comparisons */
            bool operator== (BN::RawSrcPtr other) const;
            bool is_zero () const;

            /* */
            int num_bytes () const;
            static void add (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b);

            /* conversion */
            operator BN::RawSrcPtr () const;
            void to_bytes (std::vector<unsigned char> &dst) const;
            void from_bytes (const std::vector<unsigned char> &src);

            /* */
            friend std::ostream & operator<< (std::ostream &o, const BN &v);

        private:
            BIGNUM *bn_;
        }; /* BN */

        /*****/
        class ECPoint
        {
            friend ECGroup;

        public:
            using RawSrcPtr = const EC_POINT *;

            /* constructors */
            ECPoint (const ECGroup &E);
            ECPoint (const ECGroup &E, ECPoint::RawSrcPtr Q);
            ECPoint (const ECPoint &) = delete;
            ECPoint (ECPoint &&);

            /* assignment */
            ECPoint & operator= (ECPoint::RawSrcPtr Q);
            ECPoint & operator= (const ECPoint &);
            ECPoint & operator= (ECPoint &&);

            /* destructor */
            ~ECPoint ();

            operator ECPoint::RawSrcPtr () const;

        private:
            EC_POINT *P_;
        }; /* ECPoint */

        /*****/
        class ECKey
        {
            friend ECGroup;

        public:
            /* constructors */
            ECKey (const ECGroup &E);
            ECKey (const ECKey &);
            ECKey (ECKey &&);

            /* destructor */
            ~ECKey ();

            /* assignment */
            ECKey & operator= (const ECKey &);
            ECKey & operator= (ECKey &&);

            /* getters */
            BN::RawSrcPtr get_value () const;
            ECPoint::RawSrcPtr get_ec_point () const;

        private:
            EC_KEY *key_;
        }; /* ECKey */

        /****/
        class ECGroup
        {
            /* Constructors of ECPoint and ECKey need to access ec_group_ to create
             * EC_POINT * and EC_KEY *.
             */
            friend ECPoint::ECPoint (const ECGroup &);
            friend ECPoint::ECPoint (const ECGroup &, ECPoint::RawSrcPtr);
            friend ECKey::ECKey (const ECGroup &);

        public:
            static const int P224 = NID_secp224r1;
            static const int P256 = NID_X9_62_prime256v1;
            static const int P384 = NID_secp384r1;
            static const int P521 = NID_secp521r1;

            /* constructors */
            ECGroup (SecLevel seclevel);
            ECGroup (const ECGroup &G) = delete;
            ECGroup (ECGroup &&G);

            /* destructor */
            ~ECGroup ();

            /* assignment */
            ECGroup & operator= (const ECGroup &G) = delete;
            ECGroup & operator= (ECGroup &&G);

            /* getters */
            const Mpz & order () const;

            /* */
            ECPoint::RawSrcPtr gen () const;
            bool is_on_curve (ECPoint::RawSrcPtr P) const;
            bool is_at_infinity (ECPoint::RawSrcPtr P) const;

            /* elliptic operations */
            void get_coords_of_point (BN &x, BN &y, ECPoint::RawSrcPtr P) const;
            void get_x_coord_of_point (BN &x, ECPoint::RawSrcPtr P) const;
            bool ec_point_eq (ECPoint::RawSrcPtr P, ECPoint::RawSrcPtr Q) const;
            void ec_add (ECPoint &R, ECPoint::RawSrcPtr P,
                         ECPoint::RawSrcPtr Q) const;
            void scal_mul_gen (ECPoint &R, BN::RawSrcPtr n) const;
            void scal_mul (ECPoint &R, BN::RawSrcPtr n,
                           ECPoint::RawSrcPtr P) const;
            void scal_mul (ECPoint &R, BN::RawSrcPtr m, BN::RawSrcPtr n,
                           ECPoint::RawSrcPtr P) const;

            /* arithmetic operations modulo the group order */
            void mod_order (BN &r, BN::RawSrcPtr a) const;
            void add_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const;
            void mul_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const;
            void inverse_mod_order (BN &r, BN::RawSrcPtr a) const;

        protected:
            /* utils */
            bool has_correct_order (ECPoint::RawSrcPtr P) const;
            bool is_positive_less_than_order (BN::RawSrcPtr v) const;

        private:
            EC_GROUP *ec_group_;
            Mpz order_;
            BN_CTX *ctx_;
        }; /* ECGroup */

//    #include "openssl_wrapper.inl"
/******************************************************************************/
        inline
        void random_bytes (unsigned char *buf, int num)
        {
            int ret = RAND_bytes (buf, num);
            if (ret != 1)
                throw std::runtime_error ("RAND_bytes failed in random_bytes");
        }

/******************************************************************************/
/* */
        inline
        EVP_MD_CTX * HashAlgo::new_ctx_ ()
        {
            EVP_MD_CTX *r = EVP_MD_CTX_new ();
            if (r == NULL)
                throw std::runtime_error ("EVP_MD_CTX_new failed in HashAlgo");
            return r;
        }

/* */
        inline
        HashAlgo::HashAlgo (int nid) : md_(EVP_get_digestbynid (nid)),
                                       mdctx_ (new_ctx_())
        {
            if (md_ == NULL)
                throw std::runtime_error ("could not set EVP from nid in HashAlgo");
        }

/* */
        inline
        HashAlgo::HashAlgo (SecLevel seclevel) : HashAlgo (seclevel.sha3_openssl_nid())
        {
        }

/* */
        inline
        HashAlgo::HashAlgo (const HashAlgo &H) : md_ (H.md_), mdctx_ (new_ctx_())
        {
            operator= (H);
        }

/* */
        inline
        HashAlgo::HashAlgo (HashAlgo &&H) : md_ (H.md_), mdctx_ (H.mdctx_)
        {
            H.mdctx_ = NULL;
        }

/* */
        inline
        HashAlgo::~HashAlgo ()
        {
            EVP_MD_CTX_free (mdctx_);
        }

/* */
        inline
        HashAlgo & HashAlgo::operator= (const HashAlgo &H)
        {
            md_ = H.md_;
            int ret = EVP_MD_CTX_copy_ex (mdctx_, H.mdctx_);
            if (ret != 1)
                throw std::runtime_error ("could not copy EVP_MD_CTX");
            return *this;
        }

/* */
        inline
        HashAlgo & HashAlgo::operator= (HashAlgo &&H)
        {
            md_ = H.md_;
            mdctx_ = H.mdctx_;
            H.mdctx_ = NULL;
            return *this;
        }

/* */
        inline
        int HashAlgo::digest_size () const
        {
            return EVP_MD_size (md_);
        }

/* */
        template <typename First, typename... Rem>
        inline
        HashAlgo::Digest HashAlgo::operator() (const First &first, const Rem&... rem)
        {
            int ret = EVP_DigestInit_ex (mdctx_, md_, NULL);
            if (ret != 1)
                throw std::runtime_error ("EVP_DigestInit_ex failed in HashAlgo");

            Digest h (digest_size ());
            hash_update (first, rem...);

            ret = EVP_DigestFinal_ex (mdctx_, h.data(), NULL);
            if (ret != 1)
                throw std::runtime_error ("EVP_DigestFinal_ex failed in HashAlgo");

            return h;
        }

/* */
        template <typename First, typename... Rem>
        inline
        void HashAlgo::hash_update (const First &first, const Rem&... rem)
        {
            hash_update (first);
            hash_update (rem...);
        }

/* */
        inline
        void HashAlgo::hash_update_implem (const void *ptr, size_t n)
        {
            int ret = EVP_DigestUpdate (mdctx_, ptr, n);
            if (ret != 1)
                throw std::runtime_error ("EVP_DigestUpdate failed in hash_update_implem");
        }

/* */
        template <>
        void HashAlgo::hash_update (const std::vector<unsigned char> &m)
        {
            hash_update_implem (m.data(), m.size() * sizeof(unsigned char));
        }

/* */
        template <>
        void HashAlgo::hash_update (const Mpz &v)
        {
            mpz_srcptr vptr = static_cast<mpz_srcptr> (v);
            hash_update_implem (mpz_limbs_read (vptr), v.nlimbs() * sizeof (mp_limb_t));
        }

/******************************************************************************/
/* */
        inline
        BN::BN () : bn_(BN_new())
        {
            if (bn_ == NULL)
                throw std::runtime_error ("could not allocate BIGNUM");
        }

/* */
        inline
        BN::BN (const BN &other) : bn_ (BN_dup (other.bn_))
        {
            if (bn_ == NULL)
                throw std::runtime_error ("could not duplicate BIGNUM");
        }

/* */
        inline
        BN::BN (BN &&other) : bn_(other.bn_)
        {
            other.bn_ = NULL;
        }

/* */
        inline
        BN & BN::operator= (const BN &other)
        {
            const BIGNUM *ret = BN_copy (bn_, other.bn_);
            if (ret == NULL)
                throw std::runtime_error ("could not copy BIGNUM");
            return *this;
        }

/* */
        inline
        BN & BN::operator= (BN &&other)
        {
            bn_ = other.bn_;
            other.bn_ = NULL;
            return *this;
        }

/* */
        inline
        BN::~BN ()
        {
            BN_free (bn_);
        }

/* */
        inline
        bool BN::operator== (BN::RawSrcPtr other) const
        {
            return BN_cmp (bn_, other) == 0;
        }

/* */
        inline
        bool BN::is_zero () const
        {
            return BN_is_zero (bn_);
        }

/* */
        inline
        int BN::num_bytes () const
        {
            return BN_num_bytes (bn_);
        }

/* */
        inline
        void BN::add (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b)
        {
            int ret = BN_add (r.bn_, a, b);
            if (ret != 1)
                throw std::runtime_error ("BN_add failed");
        }

/* */
        inline
        BN::operator BN::RawSrcPtr () const
        {
            return bn_;
        }

/* */
        inline
        void BN::to_bytes (std::vector<unsigned char> &dst) const
        {
            dst.resize (num_bytes());
            BN_bn2bin (bn_, dst.data());
        }

/* */
        inline
        void BN::from_bytes (const std::vector<unsigned char> &src)
        {
            const BIGNUM *ret = BN_bin2bn (src.data(), src.size(), bn_);
            if (ret == NULL)
                throw std::runtime_error ("Could not set BIGNUM from binary");
        }

/* */
        template <>
        void HashAlgo::hash_update (const OpenSSL::BN &v)
        {
            std::vector<unsigned char> bin;
            v.to_bytes (bin);
            hash_update (bin);
        }

/* */
        inline
        std::ostream & operator<< (std::ostream &o, const BN &v)
        {
            char *buf = BN_bn2dec (v);
            if (buf == NULL)
                throw std::runtime_error ("BN_bn2dec failed in operator<<");
            o << buf;
            OPENSSL_free (buf);
            return o;
        }

/****************************************************************************/
/* */
        inline
        ECPoint::ECPoint (const ECGroup &E) : P_(NULL)
        {
            P_ = EC_POINT_new (E.ec_group_);
            if (P_ == NULL)
                throw std::runtime_error ("EC_POINT_new failed in ECPoint constructor");
        }

/* */
        inline
        ECPoint::ECPoint (const ECGroup &E, ECPoint::RawSrcPtr Q) : P_(NULL)
        {
            P_ = EC_POINT_dup (Q, E.ec_group_);
            if (P_ == NULL)
                throw std::runtime_error ("EC_POINT_dup failed in ECPoint constructor");
        }

/* */
        inline
        ECPoint::ECPoint (ECPoint &&Q) : P_(Q.P_)
        {
            Q.P_ = NULL;
        }

/*
 * Assumes Q can be copied into P_ (must be init with compatible ECGroup).
 */
        inline
        ECPoint & ECPoint::operator= (ECPoint::RawSrcPtr Q)
        {
            int ret = EC_POINT_copy (P_, Q);
            if (ret != 1)
                throw std::runtime_error ("EC_POINT_copy failed in ECPoint::operator=");
            return *this;
        }

/*
 * Assumes Q can be copied into P_ (must be init with compatible ECGroup).
 */
        inline
        ECPoint & ECPoint::operator= (const ECPoint &Q)
        {
            return operator= (Q.P_);
        }

/*
 * Assumes Q can be copied into P_ (must be init with compatible ECGroup).
 */
        inline
        ECPoint & ECPoint::operator= (ECPoint &&Q)
        {
            P_ = Q.P_;
            Q.P_ = NULL;
            return *this;
        }

/* */
        inline
        ECPoint::~ECPoint ()
        {
            EC_POINT_free (P_);
        }

/* */
        inline
        ECPoint::operator ECPoint::RawSrcPtr  () const
        {
            return P_;
        }

/******************************************************************************/
/* */
        inline
        ECKey::ECKey (const ECGroup &E) : key_ (EC_KEY_new())
        {
            if (key_ == NULL)
                throw std::runtime_error ("could not allocate EC_KEY in ECKey constructor");

            int ret = EC_KEY_set_group (key_, E.ec_group_);
            if (ret != 1)
                throw std::runtime_error ("could not set group in ECKey constructor");

            ret = EC_KEY_generate_key (key_);
            if (ret != 1)
                throw std::runtime_error ("could not generate key in ECKey constructor");
        }

/* */
        inline
        ECKey::ECKey (const ECKey &K) : key_ (EC_KEY_new())
        {
            if (key_ == NULL)
                throw std::runtime_error ("could not allocate EC_KEY in ECKey constructor");

            operator= (K);
        }

/* */
        inline
        ECKey::ECKey (ECKey &&K) : key_(K.key_)
        {
            K.key_ = NULL;
        }

/* */
        inline
        ECKey::~ECKey ()
        {
            EC_KEY_free (key_);
        }

/* */
        inline
        ECKey & ECKey::operator= (const ECKey &K)
        {
            EC_KEY *ret = EC_KEY_copy (key_, K.key_);
            if (ret == NULL)
                throw std::runtime_error ("EC_KEY_copy failed in ECKey copy assignment");
            return *this;
        }

/* */
        inline
        ECKey & ECKey::operator= (ECKey &&K)
        {
            key_ = K.key_;
            K.key_ = NULL;
            return *this;
        }

/* */
        inline
        BN::RawSrcPtr ECKey::get_value () const
        {
            return EC_KEY_get0_private_key (key_);
        }

/* */
        inline
        ECPoint::RawSrcPtr ECKey::get_ec_point () const
        {
            return EC_KEY_get0_public_key (key_);
        }

/******************************************************************************/
/* */
        inline
        ECGroup::ECGroup (SecLevel seclevel) : ctx_ (BN_CTX_new())
        {
            int nid = seclevel.elliptic_curve_openssl_nid(); /* openssl curve id */
            ec_group_ = EC_GROUP_new_by_curve_name (nid);
            if (ec_group_ == NULL)
                throw std::runtime_error ("could not allocate elliptic curve");

            if (ctx_ == NULL)
                throw std::runtime_error ("could not allocate BN_CTX");

            order_ = EC_GROUP_get0_order (ec_group_);
        }

/* */
        inline
        ECGroup::ECGroup (ECGroup &&G) : ec_group_ (G.ec_group_),
                                         order_ (std::move(G.order_)),
                                         ctx_ (G.ctx_)
        {
            G.ec_group_ = NULL;
            G.ctx_ = NULL;
        }

/* */
        inline
        ECGroup::~ECGroup ()
        {
            EC_GROUP_free (ec_group_);
            BN_CTX_free (ctx_);
        }

/* */
        inline
        ECGroup & ECGroup::operator= (ECGroup &&G)
        {
            ec_group_ = G.ec_group_;
            G.ec_group_ = NULL;
            ctx_ = G.ctx_;
            G.ctx_ = NULL;
            order_ = std::move (G.order_);
            return *this;
        }

/* */
        inline
        const Mpz & ECGroup::order () const
        {
            return order_;
        }

/* */
        inline
        ECPoint::RawSrcPtr ECGroup::gen () const
        {
            return EC_GROUP_get0_generator (ec_group_);
        }

/* */
        inline
        bool ECGroup::is_on_curve (ECPoint::RawSrcPtr P) const
        {
            return EC_POINT_is_on_curve (ec_group_, P, ctx_);
        }

/* */
        inline
        bool ECGroup::is_at_infinity (ECPoint::RawSrcPtr P) const
        {
            return EC_POINT_is_at_infinity (ec_group_, P);
        }

/* */
        inline
        void ECGroup::get_coords_of_point (BN &x, BN &y, ECPoint::RawSrcPtr P) const
        {
            int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x.bn_, y.bn_, ctx_);
            if (ret != 1)
                throw std::runtime_error ("Could not get x, y coordinates");
        }

/* */
        inline
        void ECGroup::get_x_coord_of_point (BN &x, ECPoint::RawSrcPtr P) const
        {
            int ret = EC_POINT_get_affine_coordinates (ec_group_, P, x.bn_, NULL, ctx_);
            if (ret != 1)
                throw std::runtime_error ("Could not get x coordinate");
        }

/* */
        inline
        bool ECGroup::ec_point_eq (ECPoint::RawSrcPtr P, ECPoint::RawSrcPtr Q) const
        {
            return EC_POINT_cmp (ec_group_, P, Q, ctx_) == 0;
        }

/* */
        inline
        void ECGroup::ec_add (ECPoint &R, ECPoint::RawSrcPtr P,
                              ECPoint::RawSrcPtr Q) const
        {
            int ret = EC_POINT_add (ec_group_, R.P_, P, Q, ctx_);
            if (ret != 1)
                throw std::runtime_error ("EC_POINT_add failed in add");
        }

/* */
        inline
        void ECGroup::scal_mul_gen (ECPoint &R, BN::RawSrcPtr n) const
        {
            int ret = EC_POINT_mul (ec_group_, R.P_, n, NULL, NULL, ctx_);
            if (ret != 1)
                throw std::runtime_error ("EC_POINT_mul failed in scal_mul_gen");
        }

/* */
        inline
        void ECGroup::scal_mul (ECPoint &R, BN::RawSrcPtr n,
                                ECPoint::RawSrcPtr P) const
        {
            int ret = EC_POINT_mul (ec_group_, R.P_, NULL, P, n, ctx_);
            if (ret != 1)
                throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
        }

/* */
        inline
        void ECGroup::scal_mul (ECPoint &R, BN::RawSrcPtr m, BN::RawSrcPtr n,
                                ECPoint::RawSrcPtr P) const
        {
            int ret = EC_POINT_mul (ec_group_, R.P_, m, P, n, ctx_);
            if (ret != 1)
                throw std::runtime_error ("EC_POINT_mul failed in scal_mul");
        }

/* We assume that the order is prime (which must be the case for NIST curves) */
        inline
        bool ECGroup::has_correct_order (ECPoint::RawSrcPtr G) const
        {
            if (is_at_infinity (G))
                return false;

            if (!is_on_curve (G))
                return false;

            ECPoint T (*this);

            scal_mul (T, EC_GROUP_get0_order (ec_group_), G);
            return is_at_infinity (T.P_);
        }

/* */
        inline
        void ECGroup::mod_order (BN &r, BN::RawSrcPtr a) const
        {
            int ret = BN_nnmod (r.bn_, a, EC_GROUP_get0_order (ec_group_), ctx_);
            if (ret != 1)
                throw std::runtime_error ("BN_nnmod failed");
        }

/* */
        inline
        void ECGroup::add_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const
        {
            int ret = BN_mod_add (r.bn_, a, b, EC_GROUP_get0_order (ec_group_), ctx_);
            if (ret != 1)
                throw std::runtime_error ("BN_mod_add failed");
        }

/* */
        inline
        void ECGroup::mul_mod_order (BN &r, BN::RawSrcPtr a, BN::RawSrcPtr b) const
        {
            int ret = BN_mod_mul (r.bn_, a, b, EC_GROUP_get0_order (ec_group_), ctx_);
            if (ret != 1)
                throw std::runtime_error ("BN_mod_mul failed");
        }

/* */
        inline
        void ECGroup::inverse_mod_order (BN &r, BN::RawSrcPtr a) const
        {
            const BIGNUM *ret = BN_mod_inverse (r.bn_, a, EC_GROUP_get0_order (ec_group_),
                                                ctx_);
            if (ret == NULL)
                throw std::runtime_error ("could not inverse modulo order");
        }

/* */
        inline
        bool ECGroup::is_positive_less_than_order (BN::RawSrcPtr v) const
        {
            return !BN_is_negative (v) && !BN_is_zero (v)
                   && BN_cmp (v, EC_GROUP_get0_order (ec_group_)) < 0;
        }

    }; /* namespace OpenSSL */

}

//#include "bicycl/qfi.hpp"
namespace BICYCL
{
    /* forward declaration */
    class ClassGroup; /* needed to declare it friend of QFI */
    class QFICompressedRepresentation;

    /**
     * Binary forms of imaginary quadratic fields.
     *
     * The form is always primitive (gcd (a,b,c) = 1), in reduced form and with a
     * positive (It implies that c is also positive).
     * All public methods assumed that the input forms satisfy these assumptions
     * and ensure that the output forms also satisfy these assumptions.
     *
     * Protected methods do not necessarily respect these assumptions.
     */
    class QFI
    {
    protected:
        Mpz a_, b_, c_;

    public:
        /** default ctor, set the form to (1,1,1) */
        QFI ();
        /** Use with care */
        QFI (const Mpz &a, const Mpz &b, const Mpz &c, bool bypass_check=false);
        QFI (const QFI & other) = default;
        QFI (const QFICompressedRepresentation &compressed_form, const Mpz &disc);
        QFI (QFI && other) = default;

        /* assignment operators */
        QFI & operator= (const QFI & other) = default;
        QFI & operator= (QFI && other) = default;

        /* comparison operators */
        bool operator== (const QFI & other) const;

        bool is_equal(const QFI & other) const {
            return *this == other;
        }

        inline static QFI copy_from(const QFI &v) {
            return QFI(v);
        }

        /** Getter for the coefficient \f$a\f$ of the form */
        const Mpz & a () const;
        /** Getter for the coefficient \f$b\f$ of the form */
        const Mpz & b () const;
        /** Getter for the coefficient \f$c\f$ of the form */
        const Mpz & c () const;

        /** Return the discriminant of the form */
        Mpz discriminant () const;

        /** Return \c true if the form the neutral form, \c false otherwise */
        bool is_one () const;

        /* */
        void neg ();

        /* */
        Mpz eval (const Mpz &, const Mpz &) const;

        /* */
        QFICompressedRepresentation compressed_repr () const;

        /* */
        void lift (const Mpz &);
        void lift_2exp (unsigned int);
        void to_maximal_order (const Mpz &, const Mpz &, bool);
        void to_maximal_order_2exp (unsigned int, const Mpz &, bool);

        Mpz kernel_representative (const Mpz &, const Mpz &) const;
        Mpz kernel_representative_2exp (size_t, const Mpz &) const;

        /* I/O */
        friend std::ostream & operator<< (std::ostream &, const QFI &);

    protected:
        void set_c_from_disc (const Mpz &disc);

        /* methods for reduction */
        void normalize ();
        void normalize (Mpz &tmp0, Mpz &tmp1);
        void rho ();
        void rho (Mpz &tmp0, Mpz &tmp1);
        void reduction ();
        void reduction (Mpz &tmp0, Mpz &tmp1);

        /* */
        void prime_to (const Mpz &l);
        void prime_to_2exp ();

        /* compositions and exponentiations */
        static void nucomp (QFI &, const QFI &, const QFI &, const Mpz &,
                            bool negf2);
        static void nucomp (QFI &, const QFI &, const QFI &, const Mpz &,
                            bool negf2, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &,
                            Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &,
                            Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &,
                            Mpz &, Mpz &, Mpz &, Mpz &, Mpz &);
        static void nudupl (QFI &, const QFI &, const Mpz &);
        static void nudupl (QFI &, const QFI &, const Mpz &, Mpz &, Mpz &,
                            Mpz &, Mpz &, Mpz &, Mpz &, Mpz &, Mpz &);
        static void nupow (QFI &, const QFI &, const Mpz &, const Mpz &) ;
        static void nupow (QFI &, const QFI &, const Mpz &, const QFI &,
                           const Mpz &, const Mpz &);
        static void nupow (QFI &, const QFI &, const Mpz &, size_t, size_t,
                           const QFI &, const QFI &, const QFI &, const Mpz &);

        /* friend class */
        friend ClassGroup;
    };

    /*
     * Ref: https://eprint.iacr.org/2020/196.pdf (algo 2 and 3)
     */
    class QFICompressedRepresentation
    {
    public:
        const Mpz ap;
        const Mpz g;
        const Mpz tp;
        const Mpz b0;
        const bool is_neg;

        QFICompressedRepresentation () = delete;
        QFICompressedRepresentation (const Mpz &, const Mpz &, const Mpz &,
                                     const Mpz &, bool);

        /* getters */
        size_t nbits () const;

        /* I/O */
        friend std::ostream & operator<< (std::ostream &,
                                          const QFICompressedRepresentation &);
    };

    /** Class groups of binary forms of imaginary quadratic fields.
     */
    class ClassGroup
    {
    protected:
        Mpz disc_;
        Mpz default_nucomp_bound_;
        mutable Mpz class_number_bound_;

    public:
        ClassGroup (const Mpz &discriminant);

        /* getters */
        const Mpz & discriminant () const;
        const Mpz & default_nucomp_bound () const;

        /* create qfi */
        QFI one () const;
        QFI primeform (const Mpz &) const;
        template <size_t ngens=10, unsigned long coeff_bound=(1U << 16)>
        QFI random (RandGen &randgen) const;

        /* */
        const Mpz & class_number_bound () const;

        /* */
        void nucomp (QFI &, const QFI &, const QFI &) const;
        void nucompinv (QFI &, const QFI &, const QFI &) const;
        void nudupl (QFI &, const QFI &) const;
        void nudupl (QFI &, const QFI &, size_t) const;
        void nupow (QFI &, const QFI &, const Mpz &) const;
        void nupow (QFI &, const QFI &, const Mpz &, const QFI &,
                    const Mpz &) const;
        void nupow (QFI &, const QFI &, const Mpz &, size_t, size_t, const QFI &,
                    const QFI &, const QFI &) const;
    };

//  #include "qfi.inl"
    inline
    QFI::QFI () : a_(1UL), b_(1UL), c_(1UL)
    {
    }

/* */
    inline
    QFI::QFI (const Mpz &a, const Mpz &b, const Mpz &c, bool bypass_check)
            : a_(a), b_(b), c_(c)
    {
        if (!bypass_check)
        {
            if (discriminant().sgn() >= 0)
                throw std::runtime_error ("form must have negative discriminant");

            Mpz g;
            Mpz::gcd (g, a_, b_);
            Mpz::gcd (g, g, c_);
            if (g != 1UL)
                throw std::runtime_error ("form must be primitive");

            if (a_.sgn() <= 0)
                throw std::runtime_error ("the coeff a of the form must be positive");

            if (Mpz::cmpabs (a_, b_) <= 0 && a_ != b_)
                throw std::runtime_error ("form must be normal");

            if (a_ > c_ || (a_ == c_ && b_.sgn() < 0))
                throw std::runtime_error ("form must be reduced");
        }
    }

/* */
    inline
    bool QFI::operator== (const QFI &other) const
    {
        return a_ == other.a_ && b_ == other.b_ && c_ == other.c_;
    }

/* */
    inline
    QFI::QFI (const QFICompressedRepresentation &c, const Mpz &disc)
            : QFI()
    {
        if (c.g.is_zero() && c.tp.is_zero() && c.b0.is_zero() && not c.is_neg)
        {
            a_ = c.ap;
            b_ = 0UL;
            set_c_from_disc (disc);
        }
        else if (c.tp.is_zero())
        {
            a_ = c.g;
            b_ = c.g;
            set_c_from_disc (disc);
        }
        else
        {
            Mpz t, x, s, sp, bp, f, l;
            Mpz::mul (a_, c.ap, c.g);
            Mpz::mul (t, c.tp, c.g);

            Mpz::mul (x, t, t);
            Mpz::mod (x, x, a_);
            Mpz::mul (x, x, disc);
            Mpz::mod (x, x, a_);  /* x <- t^2*disc mod a */

            Mpz::sqrt (s, x);
            Mpz::divexact (sp, s, c.g);
            Mpz::mod_inverse (bp, c.tp, c.ap); /* typo in the article: t' not t */
            Mpz::mul (bp, bp, sp);
            Mpz::mod (bp, bp, c.ap);

            Mpz::abs (f, c.g);
            Mpz::lcm (l, f, c.ap);
            while (l < a_)
            {
                Mpz::add (f, f, 1);
                Mpz::lcm (l, f, c.ap);
            }

            Mpz::CRT (b_, bp, c.ap, c.b0, f);
            if (c.is_neg)
                b_.neg();
            set_c_from_disc (disc);
        }
    }

/* */
    inline
    const Mpz & QFI::a () const
    {
        return a_;
    }

/* */
    inline
    const Mpz & QFI::b () const
    {
        return b_;
    }

/* */
    inline
    const Mpz & QFI::c () const
    {
        return c_;
    }

/*
 * Return the discriminant of the qfi.
 */
    inline
    Mpz QFI::discriminant () const
    {
        Mpz d;
        Mpz::mul (d, a_, c_);     /* a*c */
        Mpz::mulby4 (d, d);       /* 4*a*c */
        Mpz::submul (d, b_, b_);  /* 4*a*c - b^2 */
        d.neg();                  /* d = b^2 - 4*a*c */
        return d;
    }

/*
 * return true if the form is the neutral element of the class group
 */
    inline
    bool QFI::is_one () const
    {
        return a_.is_one(); /* assume the form is reduced */
    }

/*
 * Inverse the qfi
 * The inverse of the form (a, b, c) is (a, -b, c).
 *
 * As we assumed the input is in reduced form and we want to output a reduced
 * form, there are some corner cases:
 *  - if a == c: (a, -b, c) is not reduced (we need the second coeff to be
 *    nonnegative in this case), but (c, b, a) is an equivalent reduced form. As
 *    a == c, there is nothing to do in this case.
 *  - if a == b: (a, -b, c) is not reduced (we need the second coeff to be in
 *    ]-a, a]). But (a, -b+2*a, a-b+c) = (a, b, c) is an equivalent reduced
 *    form. Again there is nothing to do in this case.
 *  - otherwise a < c and |b| < a and (a, -b, c) is in reduced form.
 */
    inline
    void QFI::neg ()
    {
        if (a_ != c_ && a_ != b_)
            b_.neg();
    }

/* */
    inline
    Mpz QFI::eval (const Mpz &x, const Mpz &y) const
    {
        Mpz v(0UL), t;
        Mpz::mul (t, x, x);
        Mpz::mul (v, a_, t);
        Mpz::mul (t, x, y);
        Mpz::addmul (v, b_, t);
        Mpz::mul (t, y, y);
        Mpz::addmul (v, c_, t);
        return v;
    }

/* */
    inline
    QFICompressedRepresentation QFI::compressed_repr () const
    {
        Mpz zero (0UL), one(1UL);

        if (b_.is_zero())
            return QFICompressedRepresentation (a_, zero, zero, zero, false);
        else if (a_ == b_)
            return QFICompressedRepresentation (one, a_, zero, zero, false);
        else
        {
            Mpz b, g, ap, f, l, b0;
            bool is_neg = (b_.sgn() < 0);
            Mpz::abs (b, b_);

            Mpz s(b), sp (a_), t(1UL), tp(0UL), sq, q;
            Mpz::sqrt (sq, a_);
            while (s >= sq)
            {
                Mpz::fdiv_qr (q, sp, sp, s);
                Mpz::swap (sp, s);
                Mpz::submul (tp, q, t);
                Mpz::swap (tp, t);
            }

            Mpz::gcd (g, a_, t);

            Mpz::divexact (ap, a_, g);
            Mpz::divexact (tp, t, g);

            Mpz::abs (f, g);
            Mpz::lcm (l, f, ap);
            while (l < a_)
            {
                Mpz::add (f, f, 1);
                Mpz::lcm (l, f, ap);
            }

            Mpz::mod (b0, b, f);
            return QFICompressedRepresentation (ap, g, tp, b0, is_neg);
        }
    }

/*
 * Lift the qfi into an qfi of discriminant l^2 times the discriminant of the
 * form.
 *
 * Assumes l is a prime power.
 *
 * Ref: Algorithm 2 (GoToNonMaxOrder) of [HJPT1998]_.
 *
 * The l-lift of f=(a,b,c) is (a, l*b, l^2*c) if a is prime to l.
 * So, first we need to move f to a an equivalent representation with the first
 * coeff prime to l. Then we apply the above formula. And finally we reduce the
 * new form.
 */
    inline
    void QFI::lift (const Mpz &l)
    {
        prime_to (l);
        /* a stays the same, b is set to b*l and c is set to c*l^2 */
        Mpz::mul (b_, b_, l);
        Mpz::mul (c_, c_, l);
        Mpz::mul (c_, c_, l);
        reduction();
    }

/*
 * Same as QFI::lift for the case of power of l=2^k.
 */
    inline
    void QFI::lift_2exp (unsigned int k)
    {
        prime_to_2exp ();
        /* a stays the same, b is set to b*2^k and c is set to c*2^(2*k) */
        Mpz::mulby2k (b_, b_, k);
        Mpz::mulby2k (c_, c_, 2*k);
        reduction();
    }

/*
 * Move the qfi into the maximal order.
 *
 * Assumptions:
 *  - l is a odd prime power
 *  - DeltaK is a fundamental discriminant and odd
 *  - the discriminant is l^2 times DeltaK
 *
 * Ref: Algorithm 3 (GoToMaxOrder) of [HJPT1998]_.
 *
 * The image of (a,b,c) is, if a is prime to l, (a, bu + adv, ...) where
 *    - 1 = u*l + v*a (so a must be prime to l).
 *    - d = discriminant % 2
 * So, first we need to move f to a an equivalent representation with the
 * first coeff prime to l. Then we apply the above formula.
 * Then, if with_reduction is true (the default), the form is finally reduced.
 */
    inline
    void QFI::to_maximal_order (const Mpz &l, const Mpz &DeltaK,
                                bool with_reduction=true)
    {
        Mpz tmp0, g0, g1;
        prime_to (l);
        Mpz::gcdext (tmp0, g0, g1, l, a_);
        /* As we assume that DeltaK and l are odd, d equals 1 */
        Mpz::mul (b_, b_, g0);
        Mpz::addmul (b_, a_, g1);
        set_c_from_disc (DeltaK);
        if (with_reduction)
            reduction();
    }

/*
 * Same as QFI::to_maximal_order for the case of power of l=2^k.
 * Assumptions:
 *  - DeltaK is a fundamental discriminant and even
 *  - the discriminant is l^2 times DeltaK
 */
    inline
    void QFI::to_maximal_order_2exp (unsigned int k, const Mpz &DeltaK,
                                     bool with_reduction=true)
    {
        prime_to_2exp ();
        Mpz u, v;
        Mpz::mod_inverse_2k (v, a_, k, u); /* u is used as temp variable here */
        Mpz::mul (u, v, a_);
        Mpz::sub (u, u, 1);
        u.neg();
        Mpz::divby2k (u, u, k); /* u = (1-v*a)/2^k */
        /* As we assume that DeltaK and l are even, d equals 0 */
        Mpz::mul (b_, b_, u);
        set_c_from_disc (DeltaK);

        if (with_reduction)
            reduction();
    }

/*
 * Compute a representative of the form in (OK / lOK)* / (Z/lZ)*.
 *
 * Assumption:
 *  - the discriminant of the form is l^2 * DeltaK
 *  - l is a prime power
 *  - l and DeltaK are odd
 *  - the form belongs to the kernel of the projection from Cl(O) to
 *    Cl(O_DeltaK) (std::invalid_argument is thrown otherwhise)
 */
    inline
    Mpz QFI::kernel_representative (const Mpz &l, const Mpz &DeltaK) const
    {
        Mpz tmp0, tmp1, g0, g1;
        /* Move f to the O_DeltaK
         */
        QFI ft(*this);
        ft.to_maximal_order (l, DeltaK, false); /* no reduction */

        /* Reduce ft and build gamma while doing it. Each time we apply rho to the
         * form (a,b,c) gamma is multiplied by (b+sqrt(DeltaK))/(2*a).
         * We do not care about the 2*a in the denominator as at the end we are going
         * to compute a representative of gamma^(-1) in the kernel as -g1/g0 mod l. We
         * just have to remove common factor in g0 and g1 before taking the invert.
         */
        int cmp;
        g0 = 1UL; g1 = 0UL; /* start with g = 1 + 0 sqrt(DeltaK) */
        ft.normalize (tmp0, tmp1);
        while ((cmp = Mpz::cmpabs (ft.a_, ft.c_)) > 0) /* while a larger than c */
        {
            Mpz::mul (tmp0, g1, DeltaK);    /* tmp0 <- g1*DeltaK */
            Mpz::mul (g1, g1, ft.b_);       /* g1 <- g1*b */
            Mpz::add (g1, g1, g0);          /* g1 <- g1*b + g0 */
            Mpz::mul (g0, g0, ft.b_);       /* g0 <- g0*b */
            Mpz::add (g0, g0, tmp0);        /* g0 <- g0*b + g1*DeltaK */

            ft.rho (tmp0, tmp1);
        }

        /* Throw invalid_argument if f is not (1, 1, ...), the reduced neutral form
         * for odd values of DeltaK.
         */
        if (ft.a_ != 1UL or ft.b_ != 1UL)
            throw std::invalid_argument ("the form is not in the kernel");

        Mpz::gcd (tmp1, g0, g1);
        Mpz::divexact (g0, g0, tmp1);
        Mpz::divexact (g1, g1, tmp1);

        Mpz::mod_inverse (tmp0, g0, l);
        g1.neg();
        Mpz::mul (tmp0, tmp0, g1);
        Mpz::mod (tmp0, tmp0, l);

        return tmp0;
    }

/*
 * Compute a representative of the form in (OK / 2^kOK)* / (Z/2^kZ)*.
 *
 * Assumption:
 *  - the discriminant of the form is 2^(2*k) * DeltaK
 *  - DeltaK is even
 *  - the form belongs to the kernel of the projection from Cl(O) to
 *    Cl(O_DeltaK) (std::invalid_argument is thrown otherwhise)
 */
    inline
    Mpz QFI::kernel_representative_2exp (size_t k, const Mpz &DeltaK) const
    {
        Mpz tmp0, tmp1, g0, g1;
        QFI ft(*this);
        ft.to_maximal_order_2exp (k, DeltaK, false); /* no reduction */

        /* Reduce ft and build gamma while doing it. */
        int cmp;
        g0 = 1UL; g1 = 0UL; /* start with g = 1 + 0 sqrt(DeltaK) */
        ft.normalize (tmp0, tmp1);
        while ((cmp = Mpz::cmpabs (ft.a_, ft.c_)) > 0) /* while a larger than c */
        {
            Mpz::mul (tmp0, g1, DeltaK);    /* tmp0 <- g1*DeltaK */
            Mpz::mul (g1, g1, ft.b_);       /* g1 <- g1*b */
            Mpz::add (g1, g1, g0);          /* g1 <- g1*b + g0 */
            Mpz::mul (g0, g0, ft.b_);       /* g0 <- g0*b */
            Mpz::add (g0, g0, tmp0);        /* g0 <- g0*b + g1*DeltaK */

            ft.rho (tmp0, tmp1);
        }

        /* Throw invalid_argument if f is not (1, 0, ...), the reduced neutral form
         * for even values of DeltaK.
         */
        if (ft.a_ != 1UL or ft.b_.sgn() != 0)
            throw std::invalid_argument ("the form is not in the kernel");

        size_t v = g0.val2();
        Mpz::divby2k (g0, g0, v);
        Mpz::divby2k (g1, g1, v);

        Mpz::mod_inverse_2k (tmp0, g0, k, tmp1);
        Mpz::mod2k (tmp0, tmp0, k);
        g1.neg();
        Mpz::mul (tmp0, tmp0, g1);
        Mpz::mod2k (tmp0, tmp0, k);

        return tmp0;
    }


/* */
    inline
    std::ostream & operator<< (std::ostream &o, const QFI &f)
    {
        return o << "(" << f.a_ << ", " << f.b_ << ", " << f.c_ << ")";
    }

/*
 * Set the coefficient c of the qfi given its discriminant.
 * Assumes that the coefficients a and b are already set and that 4*a
 * divides b^2-disc.
 */
    inline
    void QFI::set_c_from_disc (const Mpz &disc)
    {
        Mpz::mul (c_, b_, b_);      /* b^2 */
        Mpz::sub (c_, c_, disc);    /* b^2-disc */
        Mpz::divexact (c_, c_, a_); /* (b^2-disc)/a */
        Mpz::divby4 (c_, c_);       /* (b^2-disc)/(4*a) */
    }

/*
 * Normalize the qfi.
 * The form f is called normal if -a < b <= a.
 *
 * Note: for normalization (when not called via rho), 99% of the time q is
 * -1 (and 99.9% we have |q| <= 2)
 */
    inline
    void QFI::normalize ()
    {
        Mpz q, r;
        normalize (q, r);
    }

    inline
    void QFI::normalize (Mpz &q, Mpz &r)
    {
        Mpz::cdiv_qr (q, r, b_, a_); /* b = q*a + r    and    -a < r <= 0 */
        if (q.is_odd())
            Mpz::add (r, r, a_);
        Mpz::divby2 (q, q); /* divide q by 2 */
        /* Now we have b = (2*a)*q + r    and   -a < r <= a */
        Mpz::swap (b_, r);
        Mpz::add (r, b_, r);
        Mpz::divby2 (r, r);
        Mpz::submul (c_, q, r);
    }

/*
 * Apply the rho transformation to the qfi
 * rho(f=(a,b,c)) is defined as the normalization of the form (c,-b,a)
 */
    inline
    void QFI::rho ()
    {
        Mpz q, r;
        rho (q, r);
    }

    inline
    void QFI::rho (Mpz &q, Mpz &r)
    {
        /* The 2 versions seems to be equivalent (first even seems slightly
         * faster) */
#if 1
        Mpz::swap (a_, c_);
        b_.neg();
        normalize (q, r);
#else
        Mpz::fdiv_qr (q, r, b_, c_); /* b = q*c + r    and   0 <= r < c */
  if (q.is_odd())
    Mpz::sub (r, r, c_);
  mpzc_div_q_2exp (q, q, 1); /* divide q by 2 */
  /* Now we have b = (2*c)*q + r    and   -c <= r < c,
   * It implies     -c < -b + (2*c)*q <= c
   */
  Mpz::add (b_, b_, r);
  Mpz::divby2 (b_, b_);
  Mpz::submul (a_, q, b_);
  mpz_neg (b_, r);
  Mpz::swap (a_, c_);
#endif
    }

/*
 * Reduce the qfi f.
 * The form f is reduced if the form is
 *      normal (-a < b <= a)
 *    and
 *      a < c   or    a = c and b >= 0.
 */
    inline
    void QFI::reduction ()
    {
        Mpz t0, t1;
        reduction (t0, t1);
    }

    inline
    void QFI::reduction (Mpz &t0, Mpz &t1)
    {
        int cmp;
        normalize (t0, t1);
        /* We know a and c > 0, do not consider signs for comparisons */
        while ((cmp = Mpz::cmpabs (a_, c_)) > 0) /* while a larger than c */
            rho (t0, t1);

        if (cmp == 0 && b_.sgn() < 0) /* if a == c, we need b positive */
            b_.neg();
    }

/*
 * Modify the form into an equivalent qfi such that l is coprime with its first
 * coeff.
 *
 * Assumes l is a prime power.
 *
 * Ref: Algorithm 1 (FindIdealPrimeTo) of [HJPT1998]_.
 *
 * Remark: the output form is not necessarily reduced.
 */
    inline
    void QFI::prime_to (const Mpz &l)
    {
        Mpz g;
        Mpz::gcd (g, a_, l);
        if (g > 1UL)
        {
            Mpz::gcd (g, c_, l);
            if (g > 1UL) /* transform f into (a+b+c, -b-2a, a) */
            {
                Mpz::add (c_, c_, a_);
                Mpz::add (c_, c_, b_);
                Mpz::add (b_, b_, a_);
                Mpz::add (b_, b_, a_);
                b_.neg();
                Mpz::swap (a_, c_);
            }
            else /* c_ is coprime to l: transform f into (c, -b, a) */
            {
                Mpz::swap (a_, c_);
                b_.neg();
            }
        }
        /* else do nothing if a_ is already coprime to l */
    }

/*
 * Same as QFI::prime_to for the case of power of 2.
 */
    inline
    void QFI::prime_to_2exp ()
    {
        if (a_.is_even())
        {
            if (c_.is_even()) /* transform f into (a+b+c, -b-2a, a) */
            {
                Mpz::add (c_, c_, a_);
                Mpz::add (c_, c_, b_);
                Mpz::add (b_, b_, a_);
                Mpz::add (b_, b_, a_);
                b_.neg();
                Mpz::swap (a_, c_);
            }
            else /* c_ is odd: transform f into (c, -b, a) */
            {
                Mpz::swap (a_, c_);
                b_.neg();
            }
        }
        /* else do nothing if a_ is already odd */
    }

#ifdef BICYCL_WITH_TIMINGS
    static uint64_t _nucomp_ttot, _nucomp_tgcdext, _nucomp_tpartial, _nucomp_treduc,
                _nudupl_ttot, _nudupl_tgcdext, _nudupl_tpartial, _nudupl_treduc;
#endif
#ifdef BICYCL_WITH_COUNTS
    static uint64_t _nucomp_ncalls, _nudupl_ncalls;
#endif

/*
 * Compute the composition of two qfi.
 *
 * Input:
 *  - f1 and f2: the two input qfi
 *  - L: bound for partial reduction
 *  - negf2: negate f2 before doing the composition
 * Ouput:
 *  - r: output qfi corresponding to the composition of f1 with f2 (or
 *        f2^(-1) if negf2 is nonzero).
 *
 * Assumption: f1 and f2 must have the same discriminant.
 *
 * Note on the algorithm:
 *  Ref: "A Note on NUCOMP", Alfred J. van der Poorten in Mathematics of
 *        computation, vol 72, number 244. 2003.
 *
 *  Let (ai, bi, ci) be the coefficients of the input form fi.
 *  m and s are defined as:
 *    s = (b1+b2)/2
 *    m = (b2-b1)/2
 *
 *  The goal of the algorithm is to find a 2x4 matrix
 *
 *      Ax Bx Cx Dx
 *      Ay By Cy Dy
 *
 *  such that the minors are:
 *          minor_AB = a1, minor_AC = a2,
 *          minor_AD = s, minor_BC = m,
 *          minor_BD = c2, minor_CD = c1
 *
 *  The returned qfi is then computed as
 *    r = (By*Cy-Ay*Dy, (Ax*Dy+Ay*Dx)-(Bx*Cy+By*Cx), Bx*Cx-Ax*Dx)
 *
 *  The 2x4 matrix can be multiplied on the left by any matrix of SL2(Z).
 *
 *  The two following vectors are orthogonal to the two rows:
 *    v1 = (m, -a2, a1, 0)
 *    v2 = (c2, -s, 0, a1)
 *  This fact allows to retrieve Cx, Cy, Dx, Dy from Ax, Ay, Bx, By.
 *    v1 orthogonal to row1 <=> m*Ax - a2*Bx + a1*Cx == 0
 *    v1 orthogonal to row2 <=> m*Ay - a2*By + a1*Cy == 0
 *    v2 orthogonal to row1 <=> c2*Ax - s*Bx + a1*Dx == 0
 *    v2 orthogonal to row2 <=> c2*Ay - s*By + a1*Dy == 0
 *
 *  A possible solution matrix (used as the initial matrix) is given by
 *
 *    G  (m*v)/H+(l*By)/H   -m*x*u+y*c1+k*a2/G  -x*(v*c1+u*c2) + k*s/G
 *    0  a1/G               a2/G                s/G
 *
 *  where F = gcd (a1, a2) = u*a1 + v*a2
 *        G = gcd (F, s) = x*F + y*s
 *        H = F/G
 *        l = y*(v*c1+u*c2) + k*H
 *        k can be any integer
 *
 *  Then a partial euclidean algorithm is computed with Bx and By to reduce
 *  the size of the coefficients of the matrix.
 *  The returned form is computed with this new matrix.
 *
 * TODO: reduce the number of scratch variables
 */
    inline
    void QFI::nucomp (QFI &r, const QFI &f1, const QFI &f2,
                      const Mpz &L, bool negf2, Mpz &Ax, Mpz &Ay, Mpz &Bx,
                      Mpz &By, Mpz &Cx, Mpz &Cy, Mpz &Dx, Mpz &Dy, Mpz &m,
                      Mpz &s, Mpz &F, Mpz &u, Mpz &v, Mpz &x, Mpz &y, Mpz &H,
                      Mpz &t0, Mpz &t1, Mpz &l, Mpz &q, Mpz &by, Mpz &m00,
                      Mpz &m01, Mpz &m10, Mpz &m11)
    {
#ifdef BICYCL_WITH_COUNTS
        _nucomp_ncalls++;
#endif
#ifdef BICYCL_WITH_TIMINGS
        uint64_t _time, _time0 = get_realtime_ns();
#endif
        mp_size_t Lsize = L.nlimbs(); /* depending on log2(L) may need to do -1 */

        Mpz::add (s, f1.b_, f2.b_);
        Mpz::divby2 (s, s);
        Mpz::sub (m, f2.b_, s);

        if (negf2)
        {
            Mpz::swap (s, m);
            s.neg();
            m.neg();
        }

        /* F = gcd (a1, a2) = u*a1 + v*a2 */
#ifdef BICYCL_WITH_TIMINGS
        _time = get_realtime_ns();
#endif
        Mpz::gcdext (F, u, v, f1.a_, f2.a_);
#ifdef BICYCL_WITH_TIMINGS
        _nucomp_tgcdext += get_realtime_ns() - _time;
#endif
        if (F.is_one())
        {
            Ax = 1UL;
            Mpz::mul (Bx, m, v); /* Bx = m*v */
            By = f1.a_;
            //Mpz::mul (Cx, m, u);
            //mpz_neg_inplace (Cx); /* Cx = -m*u */
            //Mpz::mul (Dx, v, f1.c_);
            //Mpz::addmul (Dx, u, f2.c_);
            //mpz_neg_inplace (Dx); /* Dx = -(v*c1+u*c2) */
        }
        else if (s.is_divisible_by (F))
        {
            Ax = F;
            Mpz::mul (Bx, m, v); /* Bx = m*v */
            Mpz::divexact (By, f1.a_, Ax);
            //Mpz::mul (Cx, m, u);
            //mpz_neg_inplace (Cx); /* Cx = -m*u */
            //Mpz::mul (Dx, v, f1.c_);
            //Mpz::addmul (Dx, u, f2.c_);
            //mpz_neg_inplace (Dx); /* Dx = -(v*c1+u*c2) */
        }
        else
        {
            Mpz::gcdext (Ax, x, y, F, s);
            Mpz::divexact (H, F, Ax);
            Mpz::mod (t0, f1.c_, H);
            Mpz::mod (t1, f2.c_, H);
            Mpz::mul (t0, t0, v);
            Mpz::addmul (t0, t1, u);
            Mpz::mod (t0, t0, H);
            Mpz::mul (t0, t0, y);
            Mpz::mod (l, t0, H);

            Mpz::divexact (By, f1.a_, Ax);

            Mpz::mul (t0, v, m);
            Mpz::addmul (t0, l, By);
            Mpz::divexact (Bx, t0, H);
        }
        Mpz::divexact (Cy, f2.a_, Ax);
        Mpz::divexact (Dy, s, Ax);

        /* Set Bx to Bx mod By */
        Mpz::fdiv_qr (q, Bx, Bx, By);

        /* Partially reduce Bx and By with Euclidean algorithm and compute
         * transformation matrix M.
         */
        by = By;
#ifdef BICYCL_WITH_TIMINGS
        _time = get_realtime_ns();
#endif
        Mpz::partial_euclid (m00, m01, m10, m11, Bx, by, Lsize, t0, t1);
#ifdef BICYCL_WITH_TIMINGS
        _nucomp_tpartial += get_realtime_ns() - _time;
#endif

        /* new Ay */
        Mpz::mul (Ay, m10, Ax);
        Ay.neg ();

        /* new Cx and Cy */
        Mpz::mul (Cx, Bx, Cy);
        Mpz::submul (Cx, m, m11);
        Mpz::divexact (Cx, Cx, By);
        //Mpz::mul (Cx, Cx, Ax);
        //Mpz::divexact (Cx, Cx, f1.a_);

        if (Bx.is_zero ())
        {
            Mpz::mul (Cy, f2.a_, by);
            Mpz::submul (Cy, Ay, m);
            Mpz::divexact (Cy, Cy, f1.a_);
        }
        else
        {
            Mpz::mul (Cy, Cx, by);
            Mpz::add (Cy, Cy, m);
            Mpz::divexact (Cy, Cy, Bx);
        }

        /* new Dx and Dy */
        Mpz::mul (Dx, Bx, Dy);
        Mpz::submul (Dx, f2.c_, m11);
        Mpz::divexact (Dx, Dx, By);
        //Mpz::mul (Dx, Dx, Ax);
        //Mpz::divexact (Dx, Dx, f1.a_);

        Mpz::submul (Dy, Dx, m10);
        Mpz::divexact (Dy, Dy, m11);

        /* new Ax */
        Mpz::mul (Ax, m11, Ax);

        /* r.a_ = by*Cy - Ay*Dy */
        Mpz::mul (r.a_, by, Cy);
        Mpz::submul (r.a_, Ay, Dy);

        /* r.c_ = Bx*Cx - Ax*Dx */
        Mpz::mul (r.c_, Bx, Cx);
        Mpz::submul (r.c_, Ax, Dx);

        /* r.b_ = (Ax*Dy+Ay*Dx) - (Bx*Cy + by*Cx) */
        Mpz::mul (r.b_, Ax, Dy);
        Mpz::addmul (r.b_, Ay, Dx);
        Mpz::submul (r.b_, Bx, Cy);
        Mpz::submul (r.b_, by, Cx);

#ifdef BICYCL_WITH_TIMINGS
        _time = get_realtime_ns();
#endif
        r.reduction (t0, t1);
#ifdef BICYCL_WITH_TIMINGS
        _nucomp_treduc += get_realtime_ns() - _time;
  _nucomp_ttot += get_realtime_ns() - _time0;
#endif
    }

/* */
    inline
    void QFI::nucomp (QFI &r, const QFI &f1, const QFI &f2,
                      const Mpz &L, bool negf2)
    {
        Mpz Ax, Ay, Bx, By, Cx, Cy, Dx, Dy, m, s, F, u, v, x, y, H, t0, t1, l, q, by,
                m00, m01, m10, m11;
        nucomp (r, f1, f2, L, negf2, Ax, Ay, Bx, By, Cx, Cy, Dx, Dy, m, s, F, u, v, x,
                y, H, t0, t1, l, q, by, m00, m01, m10, m11);
    }

/*
 * Special case of nucomp where f1 = f2
 * Input:
 *  - f: input qfi
 *  - L: bound for partial reduction
 * Ouput:
 *  - r: output qfi corresponding to the composition of f with itself.
 *
 * Remarks (see QFI_nucomp_scratch description for more details):
 *  Let (a, b, c) be the coefficients of the input form f.
 *
 *  The conditions on the minors become:
 *         minor_AB = minor_AC = a,
 *         minor_AD = b, minor_BC = 0,
 *         minor_BD = minor_CD = c
 *
 *  A possible solution matrix (used as the initial matrix) is given by
 *
 *    d  v*c  v*c  -u*c
 *    0  a/d  a/d  b/d
 *
 *  where d = gcd (a, b) = u*a + v*b
 *
 *  The two following vectors are orthogonal to the two rows:
 *    v1 = (0, -1, 1, 0)
 *    v2 = (c, -b, 0, a)
 *  This fact allows to retrieve Cx, Cy, Dx, Dy from Ax, Ay, Bx, By.
 *    v1 orthogonal to row1 <=> Bx == Cx
 *    v1 orthogonal to row2 <=> By == Cy
 *    v2 orthogonal to row1 <=> c*Ax - b*Bx + a*Dx == 0
 *    v2 orthogonal to row2 <=> c*Ay - b*By + a*Dy == 0
 */
    inline
    void QFI::nudupl (QFI &r, const QFI &f, const Mpz &L, Mpz &Ax, Mpz &Dx,
                      Mpz &m00, Mpz &m01, Mpz &m10, Mpz &m11, Mpz &t0,
                      Mpz &t1)
    {
#ifdef BICYCL_WITH_COUNTS
        _nudupl_ncalls++;
#endif
#ifdef BICYCL_WITH_TIMINGS
        uint64_t _time, _time0 = get_realtime_ns();
#endif

        mp_size_t Lsize = L.nlimbs();

        /* Ax = d = gcd(a,b) = u*a + v*b (u and v are stored in m11 and m01) */
#ifdef BICYCL_WITH_TIMINGS
        _time = get_realtime_ns();
#endif
        Mpz::gcdext (Ax, m11, m01, f.a_, f.b_);
#ifdef BICYCL_WITH_TIMINGS
        _nudupl_tgcdext += get_realtime_ns() - _time;
#endif

        /* Set By to a/d and Dy to b/d (resp. stored in a_ and b_) */
        if (!Ax.is_one ())
        {
            Mpz::divexact (r.a_, f.a_, Ax);
            Mpz::divexact (r.b_, f.b_, Ax);
        }
        else
        {
            r.a_ = f.a_;
            r.b_ = f.b_;
        }

        /* Set Dx to -u*c */
        Mpz::mul (Dx, f.c_, m11);
        Dx.neg ();

        /* Set Bx to v*c (stored in r.c_) */
        Mpz::mul (r.c_, f.c_, m01);

        /* Compute q = floor(Bx/By) and set Bx to Bx - q*By (= Bx mod By) and Dx
         * to Dx - q*Dy (i.e., apply matrix [[1, -q], [0, 1]])
         */
        Mpz::fdiv_qr (t0, r.c_, r.c_, r.a_);
        Mpz::submul (Dx, t0, r.b_);

        /* Partially reduce Bx and By with Euclidean algorithm and compute
         * transformation matrix M.
         */
#ifdef BICYCL_WITH_TIMINGS
        _time = get_realtime_ns();
#endif
        Mpz::partial_euclid (m00, m01, m10, m11, r.c_, r.a_, Lsize, t0, t1);
#ifdef BICYCL_WITH_TIMINGS
        _nudupl_tpartial += get_realtime_ns() - _time;
#endif

        /* apply M^-1 to (Ax, Ay) and (Dx, Dy) (Ay is stored in t1) */
        Mpz::mul (t1, Ax, m10);
        t1.neg (); /* Ax*(-m10) + Ay*m00 (with Ay=0) */
        Mpz::mul (Ax, Ax, m11); /* Ax*m11 - Ay*m10 (with Ay=0) */

        Mpz::mul (t0, Dx, m11);
        Mpz::submul (t0, r.b_, m01); /* Dx*m11 - Dy*m01 */
        Mpz::mul (r.b_, r.b_, m00);
        Mpz::submul (r.b_, Dx, m10); /* Dx*(-m10) + Dy*m00 */
        Mpz::swap (t0, Dx);

        /* temporarily store Cy*Bx (=By*Bx) in t0 */
        Mpz::mul (t0, r.a_, r.c_);

        /* a_ = By*Cy - Ay*Dy (with By == Cy) */
        Mpz::mul (r.a_, r.a_, r.a_);
        Mpz::submul (r.a_, t1, r.b_);

        /* c_ = Bx*Cx - Ax*Dx (with Bx == Cx) */
        Mpz::mul (r.c_, r.c_, r.c_);
        Mpz::submul (r.c_, Ax, Dx);

        /* b_ = (Ax*Dy+Ay*Dx) - (Bx*Cy + By*Cx) (with Bx == Cx and By == Cy) */
        Mpz::mul (r.b_, Ax, r.b_);
        Mpz::addmul (r.b_, t1, Dx);
        Mpz::mulby2 (t0, t0); /* mul by 2 */
        Mpz::sub (r.b_, r.b_, t0);

#ifdef BICYCL_WITH_TIMINGS
        _time = get_realtime_ns();
#endif
        r.reduction (t0, t1);
#ifdef BICYCL_WITH_TIMINGS
        _nudupl_treduc += get_realtime_ns() - _time;
  _nudupl_ttot += get_realtime_ns() - _time0;
#endif
    }

/* */
    inline
    void QFI::nudupl (QFI &r, const QFI &f, const Mpz &L)
    {
        Mpz Ax, Dx, m00, m01, m10, m11, t0, t1;
        nudupl (r, f, L, Ax, Dx, m00, m01, m10, m11, t0, t1);
    }


/* Helper macros for exponentiation algos (undef at the end of the file) */
#define NUDUPL(r, f) nudupl (r, f, L, t00, t01, t02, t03, t04, t05, t06, t07)
#define NUCOMP(r, f1, f2, negf2) nucomp ((r), (f1), (f2), L, negf2, t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23, t24)

/*
 * Compute the power of a qfi by an integer.
 *
 * Input:
 *  - f: input qfi
 *  - n: integer exponent
 *  - L: bound for partial reduction in nucomp and nudupl
 * Ouput:
 *  - r: output qfi corresponding to the composition f^n.
 *
 * Algorithm: binary exponentiation with windows of bits
 */
    inline
    void QFI::nupow (QFI &r, const QFI &f, const Mpz &n, const Mpz &L)
    {
        if (n.is_zero ())
        {
            r = ClassGroup (f.discriminant()).one();
        }
        else /* n != 0: binary exponentiation with abs(n) and handle sign after */
        {
            Mpz t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12,
                    t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23, t24;

            /* implem of wNAF*: a left to right wNAF (see Brian King, ACNS 2008) */
            const mp_limb_t w = 7;
            const mp_limb_t pow2w = (1UL << w); /* 2^w */
            const mp_limb_t u = (1UL<<(w-2)); /* u = 2^(w-2) */

            /* precomputation: tab[i] = f^(2*i+1)  for 0 <= i < u = 2^(w-2) */
            QFI ff(f), tab[u];

            NUDUPL (ff, f); /* f^2 */
            tab[0] = f;
            for (mp_limb_t i = 1; i < u; i++)
                NUCOMP (tab[i], tab[i-1], ff, 0); /* tab[i] <- tab[i-1]*ff */

            int j = n.nbits() - 1;
            mp_limb_t c;

            /* first digit is done out of the main loop */
            {
                /* for the first digit we know that dj=1 and c=0 */
                mp_limb_t m = n.extract_bits ((size_t) j, w);
                c = m & 0x1; /* d_{j-w+1} */
                mp_limb_t t = m + (m & 0x1); /* + d_{j-w+1} */
                size_t val2 = mpn_scan1 (&t, 0); /* note: m cannot be zero */
                size_t tau = val2 < w ? val2 : w-1;
                t >>= tau;

                r = t == 2 ? ff : tab[t>>1];
                size_t b = ((size_t) j) < w-1 ? tau+1+j-w : tau;
                for (size_t i = 0; i < b; i++)
                    NUDUPL (r, r);
                j -= w;
            }

            /* main loop */
            while (j >= 0)
            {
                mp_limb_t m = n.extract_bits ((size_t) j, w);
                mp_limb_t dj = (m >> (w-1)) & 0x1;
                mp_limb_t djmwp1 = m & 0x1;

                if (c == dj)
                {
                    NUDUPL (r, r);
                    j -= 1;
                }
                else
                {
                    int neg = c;
                    mp_limb_t t = m + djmwp1;
                    t = c ? (pow2w - t) : t;
                    c = djmwp1;

                    size_t val2 = t > 0 ? mpn_scan1 (&t, 0) : w-1;
                    size_t tau = val2 < w ? val2 : w-1;
                    t >>= tau;
                    for (size_t i = 0; i < w-tau; i++)
                        NUDUPL (r, r);
                    NUCOMP (r, r, t == 2 ? ff : tab[t>>1], neg);
                    size_t b = ((size_t) j) < w-1 ? tau+1+j-w : tau;
                    for (size_t i = 0; i < b; i++)
                        NUDUPL (r, r);
                    j -= w;
                }
            }

            if (c)
                NUCOMP (r, r, tab[0], 1);

            /* toggle the result if n is negative */
            if (n.sgn () < 0)
            {
                r.neg();
            }
        }
    }

/*
 * Multiple exponentiation.
 *
 * Input:
 *  - f0: input qfi
 *  - f1: input qfi
 *  - n0: integer exponent
 *  - n1: integer exponent
 *  - L: bound for partial reduction in nucomp and nudupl
 * Ouput:
 *  - r: output qfi corresponding to the composition f0^n0*f1^n1.
 *
 * Assumes: f0 and f1 have the same discriminant
 *          n0 and n1 are positive
 */
    inline
    void QFI::nupow (QFI &r, const QFI &f0, const Mpz &n0,
                     const QFI &f1, const Mpz &n1, const Mpz &L)
    {
        if (n0.is_zero() && n1.is_zero())
        {
            r = ClassGroup (f0.discriminant()).one();
        }
        else if (n0.is_zero())
            nupow (r, f1, n1, L);
        else if (n1.is_zero())
            nupow (r, f0, n0, L);
        else /* n0*n1 != 0: use joint sparse form */
        {
            Mpz t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12,
                    t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23, t24;

            /* precomputation */
            QFI tab[4];

            tab[0] = f0;
            tab[1] = f1;
            NUCOMP (tab[2], f0, f1, 0);
            NUCOMP (tab[3], f0, f1, 1);

            JSF jsf (n0, n1);

            /* init r */
            uint8_t most_significant = jsf[jsf.size()-1];
            if (most_significant == 0x01)
                r = tab[0];
            else if (most_significant == 0x10)
                r = tab[1];
            else if (most_significant == 0x11)
                r = tab[2];
            /* else case not needed (TODO why digit -1 is not possible ??) */

            /* main loop (skipping first nonzero digit) */
            for (size_t j = jsf.size()-1; j > 0; j--)
            {
                uint8_t d = jsf[j-1];

                NUDUPL (r, r);
                if (d == 0x01) /* f0 */
                    NUCOMP (r, r, tab[0], 0);
                else if (d == 0x03) /* f0^-1 */
                    NUCOMP (r, r, tab[0], 1);
                else if (d == 0x10) /* f1 */
                    NUCOMP (r, r, tab[1], 0);
                else if (d == 0x30) /* f1^-1 */
                    NUCOMP (r, r, tab[1], 1);
                else if (d == 0x11) /* f0 * f1 */
                    NUCOMP (r, r, tab[2], 0);
                else if (d == 0x13) /* f0^-1 * f1 */
                    NUCOMP (r, r, tab[3], 1);
                else if (d == 0x31) /* f0 * f1^-1 */
                    NUCOMP (r, r, tab[3], 0);
                else if (d == 0x33) /* f0^-1 * f1^-1 */
                    NUCOMP (r, r, tab[2], 1);
            }
        }
    }

/*
 * Multiple exponentiation.
 *
 * Input:
 *  - f: input qfi
 *  - n: integer exponent
 *  - L: bound for partial reduction in nucomp and nudupl
 *  - d, e: two positive integers such that e < d
 *  - fe: qfi such that fe = f^(2^e)
 *  - fd: qfi such that fe = f^(2^d)
 *  - fed: qfi such that fe = f^(2^(e+d))
 * Ouput:
 *  - r: output qfi corresponding to the composition f^n.
 *
 * Assumes: f0 and f1 have the same discriminant
 *          n0 and n1 are positive
 */
    void QFI::nupow (QFI &r, const QFI &f, const Mpz &n, size_t d, size_t e,
                     const QFI &fe, const QFI &fd, const QFI &fed, const Mpz &L)
    {
        if (n.is_zero ())
        {
            r = ClassGroup (f.discriminant()).one();
        }
        else if (n.nbits() < e)
        {
            nupow (r, f, n, L);
        }
        else /* n != 0: exponentiation with abs(n) and handle sign after */
        {
            Mpz t00, t01, t02, t03, t04, t05, t06, t07, t08, t09, t10, t11, t12,
                    t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23, t24;

            Mpz::mod2k (t00, n, d);
            Mpz::divby2k (t01, n, d);

            /* */
            JSF jsf (t00, t01);

            /* precomputations */
            /* tab[i] = f^d0 * fd^d1 * fe^d2 * fed^d3
             * where [ d0, d1, d2, d3] is (i+1) written in basis 3 with digits in
             * (-1, 0, 1).
             * Example: tab[20] = f^0 * fd^1 * fe^-1 * fed^1
             *          because 21 = 0*3^0 + 1*3^1 + -1*3^2 + 1*3^3
             */
            QFI tab[40];

            tab[0] = f;
            tab[2] = fd;
            tab[8] = fe;
            tab[26] = fed;

            for (size_t B = 1, pow3 = 3, i = 0; i < 3; i++, B+=pow3, pow3*=3)
            {
                for (size_t k = 0; k < B; k++)
                {
                    NUCOMP (tab[pow3+k],   tab[pow3-1], tab[k], 0);
                    NUCOMP (tab[pow3-k-2], tab[pow3-1], tab[k], 1);
                }
            }

            /* */
            r = ClassGroup (f.discriminant()).one();
            for (size_t j = jsf.size(); j > 2*e; j--)
            {
                uint8_t digh = jsf[j-1];

                NUDUPL (r, r);

                if (digh != 0)
                {
                    /* address decoding */
                    int idx = 0;
                    idx += (digh & 0x02) ?  -9 : ((digh & 0x01) ? 9 : 0);
                    idx += (digh & 0x20) ? -27 : ((digh & 0x10) ? 27 : 0);

                    bool s = idx < 0 ? true : false;
                    idx = idx < 0 ? -idx : idx;
                    NUCOMP (r, r, tab[idx-1], s);
                }
            }

            for (size_t j = 2*e; j > e; j--)
            {
                uint8_t digh = jsf[j-1];
                uint8_t digl = jsf[j-e-1];

                NUDUPL (r, r);

                if (digh != 0 || digl != 0)
                {
                    /* address decoding */
                    int idx = 0;
                    idx += (digl & 0x02) ?  -1 : ((digl & 0x01) ?  1 : 0);
                    idx += (digl & 0x20) ?  -3 : ((digl & 0x10) ?  3 : 0);
                    idx += (digh & 0x02) ?  -9 : ((digh & 0x01) ?  9 : 0);
                    idx += (digh & 0x20) ? -27 : ((digh & 0x10) ? 27 : 0);

                    bool s = idx < 0 ? true : false;
                    idx = idx < 0 ? -idx : idx;
                    NUCOMP (r, r, tab[idx-1], s);
                }
            }
        }
    }

#undef NUDUPL
#undef NUCOMP

/* */
    template <>
    void OpenSSL::HashAlgo::hash_update (const QFI &f)
    {
        hash_update (f.a());
        hash_update (f.b());
        hash_update (f.c());
    }

/******************************************************************************/
/* */
    inline
    QFICompressedRepresentation::QFICompressedRepresentation (const Mpz &ap,
                                                              const Mpz &g,
                                                              const Mpz &tp,
                                                              const Mpz &b0,
                                                              bool is_neg)
            : ap(ap), g(g), tp(tp), b0(b0), is_neg(is_neg)
    {
    }

/* */
    inline
    size_t QFICompressedRepresentation::nbits () const
    {
        /* +1 for is_neg which is a boolean */
        return ap.nbits() + g.nbits() + tp.nbits() + b0.nbits() + 1;
    }

/* */
    inline
    std::ostream & operator<< (std::ostream &o,
                               const QFICompressedRepresentation &f)
    {
        return o << "(" << f.ap << ", " << f.g << ", " << f.tp << ", " << f.b0 << ", "
                 << (f.is_neg ? "1" : "0") << ")";
    }

/******************************************************************************/
    inline
    ClassGroup::ClassGroup (const Mpz &D) : disc_(D), class_number_bound_ (0UL)
    {
        if (D.sgn() >= 0)
            throw std::invalid_argument ("the discriminant must be negative");

        unsigned long Dmod4 = D.mod4 ();
        if (Dmod4 != 0 && Dmod4 != 1)
            throw std::invalid_argument ("the discriminant must == 0, 1 mod 4");

        /* Compute the bound for nucomp: floor(|D|^1/4)
         * TODO: Find a ref on why it is better to use |D|^1/4 instead of
         * (|D|/4)^(1/4)
         */
        Mpz::abs (default_nucomp_bound_, disc_);
        Mpz::root4th (default_nucomp_bound_, default_nucomp_bound_);
    }

/* */
    inline
    const Mpz & ClassGroup::discriminant () const
    {
        return disc_;
    }

/* Return the default bound for NUCOMP */
    inline
    const Mpz & ClassGroup::default_nucomp_bound () const
    {
        return default_nucomp_bound_;
    }

/*
 * Return the neutral element of the class group, i.e., the principal qfi
 * for the discriminant of the class group.
 * It is the form [ 1, b, c ] with
 *    - b = disc % 2
 *    - c = 1/4*(b^2-disc)
 * Note that it is already in reduced form.
 */
    inline
    QFI ClassGroup::one () const
    {
        QFI f;

        f.a_ = 1UL;
        f.b_ = disc_.is_odd() ? 1UL : 0UL;
        f.c_ = disc_.is_odd() ? 1UL : 0UL;
        Mpz::sub (f.c_, f.c_, disc_);
        Mpz::divby4 (f.c_, f.c_);

        return f;
    }

/*
 * Return one of the two prime forms (l, _, _) of discriminant disc.
 * Assume l is prime and kronecker (disc, l) == 1.
 * Always choose the prime form (l, b, _) where b is the square root of
 * disc modulo 4*l in [1..l-1].
 */
    inline
    QFI ClassGroup::primeform (const Mpz &l) const
    {
        QFI r;
        r.a_ = l;
        Mpz::sqrt_mod_prime (r.b_, disc_, l);
        if (r.b_.is_odd () != disc_.is_odd ()) /* not same parity */
            Mpz::sub (r.b_, l, r.b_);
        r.set_c_from_disc (disc_);
        r.reduction();
        return r;
    }

/* /!\ not uniform, use only for tests and benchmarks */
    template <size_t ngens, unsigned long coeff_bound>
    inline
    QFI ClassGroup::random (RandGen &randgen) const
    {
        QFI r(one()), fl;
        Mpz m(coeff_bound);

        Mpz l(2UL);

        for (size_t i = 0; i < ngens; i++)
        {
            for ( ; disc_.kronecker (l) != 1; l.nextprime ());
            fl = primeform (l);
            nupow (fl, fl, randgen.random_mpz (m));
            nucomp (r, r, fl);
        }

        return r;
    }

/*
 * Return the bound on the class number. The bound B satisfies
 *      B <= class_number < 2*B
 *
 * The bound is cached
 * XXX Do we need the disc to be fundamental for the formula to work ???
 */
    inline
    const Mpz & ClassGroup::class_number_bound () const
    {
        if (class_number_bound_.is_zero()) /* computed it if not already computed */
        {
            Mpz primebound, l, tmp;

            Mpz::ceil_abslog_square (primebound, disc_);

            size_t prec = disc_.nbits() + 50;

            mpf_t acc, t, d;
            mpf_inits (acc, t, d, NULL);
            mpf_set_prec (acc, prec);
            mpf_set_prec (t, prec);
            mpf_set_prec (d, prec);

            mpf_set_ui (acc, 1);

            for (l = 2UL; l < primebound; l.nextprime())
            {
                int k = disc_.kronecker (l);
                if (k < 0)
                    Mpz::add (tmp, l, -k);
                else
                    Mpz::sub (tmp, l, k);
                mpf_set_z (t, static_cast<mpz_srcptr> (l));
                mpf_set_z (d, static_cast<mpz_srcptr> (tmp));
                mpf_div (t, t, d);
                mpf_mul (acc, acc, t);
            }

            Mpz::abs (tmp, disc_);
            Mpz::sqrt (tmp, tmp); /* tmp <- floor(sqrt(|D|)) */
            Mpz::mul (tmp, tmp, 21);
            mpf_div_ui (acc, acc, 88);
            mpf_set_z (t, static_cast<mpz_srcptr> (tmp));
            mpf_mul (t, t, acc);
            mpf_ceil (t, t);

            class_number_bound_ = t;

            mpf_clears (acc, t, d, NULL);
        }
        return class_number_bound_;
    }

    inline
    void ClassGroup::nucomp (QFI &r, const QFI &f1, const QFI &f2) const
    {
        QFI::nucomp (r, f1, f2, default_nucomp_bound(), 0);
    }

    inline
    void ClassGroup::nucompinv (QFI &r, const QFI &f1, const QFI &f2) const
    {
        QFI::nucomp (r, f1, f2, default_nucomp_bound(), 1);
    }

    inline
    void ClassGroup::nudupl (QFI &r, const QFI &f) const
    {
        QFI::nudupl (r, f, default_nucomp_bound());
    }

/* */
    inline
    void ClassGroup::nudupl (QFI &r, const QFI &f, size_t niter) const
    {
        Mpz L = default_nucomp_bound();
        Mpz t0, t1, t2, t3, t4, t5, t6, t7;
        if (niter > 0)
        {
            QFI::nudupl (r, f, L, t0, t1, t2, t3, t4, t5, t6, t7);
            for (size_t i = 1; i < niter; i++)
                QFI::nudupl (r, r, L, t0, t1, t2, t3, t4, t5, t6, t7);
        }
    }

    inline
    void ClassGroup::nupow (QFI &r, const QFI &f, const Mpz &n) const
    {
        QFI::nupow (r, f, n, default_nucomp_bound());
    }

    inline
    void ClassGroup::nupow (QFI &r, const QFI &f0, const Mpz &n0,
                            const QFI &f1, const Mpz &n1) const
    {
        QFI::nupow (r, f0, n0, f1, n1, default_nucomp_bound());
    }

    inline
    void ClassGroup::nupow (QFI &r, const QFI &f, const Mpz &n, size_t d, size_t e,
                            const QFI &fe, const QFI &fd, const QFI &fed) const
    {
        QFI::nupow (r, f, n, d, e, fe, fd, fed, default_nucomp_bound());
    }

}

//#include "bicycl/CL_HSMqk.hpp"
namespace BICYCL
{
    /**
     * Class for the cryptosystem based on the hidden subgroup membership problem.
     *
     * Ref: ??
     */
    class CL_HSMqk
    {
    protected:
        /** an odd prime. */
        Mpz q_;

        /** an positive integer */
        size_t k_;

        /** an odd prime or 1. */
        Mpz p_;

        /** q^k */
        Mpz M_;

        /** \f$ \ClDeltaK \f$ : the class group of the maximal order.
         * Its discriminant is equal to \f$ -p \times q \f$.
         */
        ClassGroup Cl_DeltaK_;

        /** \f$ \ClDelta \f$: the class group of the order of conductor
         * \f$M=q^k\f$.
         * Its discriminant is equal to \f$ -p \times q^{2k+1} \f$.
         * It contains the subgroup \f$F\f$.
         */
        ClassGroup Cl_Delta_;

        /** \c true if the compact variant is used, \c false otherwise. */
        bool compact_variant_;

        /** \c true if the large-message variant is used, \c false otherwise. */
        bool large_message_variant_;

        /** The generator of the group \f$H\f$.
         * If the compact variant is not used, the generator is an element of
         * \f$ \ClDelta \f$, else it is an element of \f$ \ClDeltaK \f$.
         */
        QFI h_;

        Mpz fud_factor_; /* folded uniform distribution factor */
        Mpz exponent_bound_; /* actual bound use to draw random values; is equal
                            * to fud_factor_ times Cl_Delta_.class_number_bound_
                            */
        /** Precomputation data: a positive integer */
        size_t d_;
        size_t e_;
        /** Precomputation data: h_^(2^e_), h_^(2^d_), h_^(d_+e_) */
        QFI h_e_precomp_;
        QFI h_d_precomp_;
        QFI h_de_precomp_;

    public:

        class SecretKey : public Mpz {
        public:
            /* constructors */
            SecretKey (const CL_HSMqk &C, const Mpz &v) : Mpz (v) {
                if (!(v.sgn() >= 0))
                    throw std::range_error ("Secret key is negative");
            }
            SecretKey (const CL_HSMqk &C, RandGen &r) : Mpz (r.random_mpz (C.secretkey_bound())) {
            }

            Mpz to_mpz() const {
                return Mpz(*this);
            }

            SecretKey copy() const {
                return SecretKey(*this);
            }
        };
        class PublicKey
        {
        protected:
            /** The actual public key: a QFI */
            QFI pk_;
            /** Precomputation data: a positive integer */
            size_t d_;
            size_t e_;
            /** Precomputation data: pk_^(2^e_), pk_^(2^d_), pk_^(d_+e_) */
            QFI pk_e_precomp_;
            QFI pk_d_precomp_;
            QFI pk_de_precomp_;

        public:
            PublicKey (const CL_HSMqk &C, const SecretKey &sk) {
                C.power_of_h (pk_, sk);

                d_ = (C.encrypt_randomness_bound().nbits () + 1)/2;
                e_ = d_/2 + 1;

                pk_de_precomp_ = pk_;
                for (size_t i = 0; i < d_+e_; i++)
                {
                    if (i == e_)
                        pk_e_precomp_ = pk_de_precomp_;
                    if (i == d_)
                        pk_d_precomp_ = pk_de_precomp_;
                    C.Cl_G().nudupl (pk_de_precomp_, pk_de_precomp_);
                }
            }

            PublicKey (const CL_HSMqk &C, const QFI &pk) : pk_(pk) {
                d_ = (C.encrypt_randomness_bound().nbits () + 1)/2;
                e_ = d_/2 + 1;

                pk_de_precomp_ = pk_;
                for (size_t i = 0; i < d_+e_; i++)
                {
                    if (i == e_)
                        pk_e_precomp_ = pk_de_precomp_;
                    if (i == d_)
                        pk_d_precomp_ = pk_de_precomp_;
                    C.Cl_G().nudupl (pk_de_precomp_, pk_de_precomp_);
                }
            }

            PublicKey copy() const {
                return PublicKey(*this);
            }

            int add(int a, int b) {
                return a + b;
            }

            const QFI & elt () const {
                return pk_;
            }

            void exponentiation (const CL_HSMqk &C, QFI &r, const Mpz &n) const {
                C.Cl_G().nupow (r, pk_, n, d_, e_, pk_e_precomp_, pk_d_precomp_, pk_de_precomp_);
            }

        };

        class CipherText;

        class ClearText : public Mpz
        {
        public:
            ClearText (const CL_HSMqk &C, const Mpz &v) : Mpz (v) {
                if (!(v.sgn() >= 0 && v < C.cleartext_bound()))
                    throw std::range_error ("Cleartext is negative or too large");
            }
            ClearText (const CL_HSMqk &C, RandGen &r) : Mpz (r.random_mpz (C.cleartext_bound())) {
            }
            ClearText (const CL_HSMqk &C, const SecretKey &sk, const CipherText &c) {
                QFI fm;

                C.Cl_G().nupow (fm, c.c1(), sk);
                if (C.compact_variant())
                    C.from_Cl_DeltaK_to_Cl_Delta (fm);

                C.Cl_Delta().nucompinv (fm, c.c2(), fm); /* c2/c1^sk */

                Mpz::operator= (C.dlog_in_F(fm));
            }
            ClearText (const CL_HSMqk &C, const ClearText &ma, const ClearText &mb) {
                Mpz::add (*this, ma, mb);
                Mpz::mod (*this, *this, C.cleartext_bound());
            }
            ClearText (const CL_HSMqk &C, const ClearText &m, const Mpz &s) {
                Mpz::mul (*this, m, s);
                Mpz::mod (*this, *this, C.cleartext_bound());
            }

            /* 重载方法，用于autocxx生成接口 */
            size_t nbits () const {
                return Mpz::nbits();
            }
            size_t ndigits () const {
                return Mpz::ndigits();
            }
            size_t nlimbs () const {
                return Mpz::nlimbs();
            }
            int sgn () const {
                return Mpz::sgn();
            }
            std::string str_value() const {
                return Mpz::str_value();
            }

            /* tests */
            bool is_zero () const {
                return Mpz::is_zero();
            }
            bool is_odd () const {
                return Mpz::is_odd();
            }
            bool is_even () const {
                return Mpz::is_even();
            }
            bool is_one () const {
                return Mpz::is_one();
            }
            bool is_prime (int reps=30) const {
                return Mpz::is_prime(reps);
            }
            bool is_divisible_by (const Mpz &d) const {
                return Mpz::is_divisible_by(d);
            }

            Mpz to_mpz() const {
                return Mpz(*this);
            }
//            ClearText mul (const ClearText &op2) const {
//                ClearText result;
//                mpz_mul (result, this->mpz_, op2.mpz_);
//                return result;
//            }
        };

        class CipherText
        {
        protected:
            /** two QFIs */
            QFI c1_, c2_;

        public:
            CipherText (const CL_HSMqk &C, const PublicKey &pk, const ClearText &m, const Mpz &r) {
                std::thread th (&CL_HSMqk::power_of_h, C, std::ref(c1_), std::cref(r)); /* c1 = h^r */

                QFI fm = C.power_of_f (m); /* fm = [q^2, q, ...]^m */
                pk.exponentiation (C, c2_, r); /* pk^r */

                if (C.compact_variant())
                    C.from_Cl_DeltaK_to_Cl_Delta (c2_);
                C.Cl_Delta().nucomp (c2_, c2_, fm); /* c2 = f^m*pk^r */

                th.join ();
            }
            CipherText (const CL_HSMqk &C, const PublicKey &pk, const CipherText &ca, const CipherText &cb, const Mpz &r) {
                std::thread th (&CL_HSMqk::power_of_h, C, std::ref(c1_), std::cref(r)); /* c1 = h^r */

                pk.exponentiation (C, c2_, r); /* pk^r */

                if (C.compact_variant())
                    C.from_Cl_DeltaK_to_Cl_Delta (c2_);
                C.Cl_Delta().nucomp (c2_, c2_, ca.c2_);
                C.Cl_Delta().nucomp (c2_, c2_, cb.c2_);

                th.join ();

                C.Cl_G().nucomp (c1_, c1_, ca.c1_);
                C.Cl_G().nucomp (c1_, c1_, cb.c1_);
            }
            CipherText (const CL_HSMqk &C, const PublicKey &pk, const CipherText &c, const Mpz &s, const Mpz &r) {
                QFI tmp;

                std::thread th (&CL_HSMqk::power_of_h, C, std::ref(c1_), std::cref(r)); /* c1 = h^r */

                pk.exponentiation (C, c2_, r); /* pk^r */
                if (C.compact_variant())
                    C.from_Cl_DeltaK_to_Cl_Delta (c2_);
                C.Cl_Delta().nupow (tmp, c.c2_, s);
                C.Cl_Delta().nucomp (c2_, c2_, tmp);

                th.join ();

                C.Cl_G().nupow (tmp, c.c1_, s);
                C.Cl_G().nucomp (c1_, c1_, tmp);
            }

            CipherText (const QFI &c1, const QFI &c2) {
                c1_ = c1;
                c2_ = c2;
            }

            /* getters */
            const QFI & c1 () const {
                return c1_;
            }
            const QFI & c2 () const {
                return c2_;
            }

            bool is_equal(const CipherText & other) const {
                return c1_ == other.c1_ && c2_ == other.c2_;
            }
        };

        /**
         * @name Constructors
         *
         * Setup of the cryptosystem
         *
         *@{
         */
        /**
         * Setup of the cryptosystem given @p q and @p p.
         */
        CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const Mpz &fud_factor,
                  bool compact_variant);
        /**
         * Same as above, using default value `false` for @p compact_variant.
         */
        CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, const Mpz &fud_factor);
        /**
         * Same as above, using default value for @p fud_factor.
         */
        CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, bool compact_variant);
        /**
         * Same as above, using default values.
         */
        CL_HSMqk (const Mpz &q, size_t k, const Mpz &p);
        /**
         * Copy constructor, only the value of compact variant can be changed.
         */
        CL_HSMqk (const CL_HSMqk &C, bool compact_variant);
        /**
         * Setup of the cryptosystem given @p q and the size of \f$\Delta_K\f$@p.
         */
        CL_HSMqk (const Mpz &q, size_t k, size_t DeltaK_nbits,
                  RandGen &randgen, const Mpz &fud_factor, bool compact_variant);
        /**
         * Setup of the cryptosystem given the size of @p q and the size of
         * \f$\Delta_K\f$@p.
         */
        CL_HSMqk (size_t q_nbits, size_t k, size_t DeltaK_nbits,
                  RandGen &randgen, const Mpz &fud_factor, bool compact_variant);
        /**
         * Setup of the cryptosystem given @p q and the desired security level.
         *
         * The equivalence between security level and the size of \f$\Delta_K\f$
         * can be found in the class \ref SecLevel.
         */
        CL_HSMqk (const Mpz &q, size_t k, SecLevel seclevel,
                  RandGen &randgen, const Mpz &fud_factor, bool compact_variant);
        /**
         * Setup of the cryptosystem given the size of @p q and the desired
         * security level.
         *
         * The equivalence between security level and the size of \f$\Delta_K\f$
         * can be found in the class \ref SecLevel.
         */
        CL_HSMqk (size_t q_nbits, size_t k, SecLevel seclevel,
                  RandGen &randgen, const Mpz &fud_factor, bool compact_variant);

        inline static CL_HSMqk copy_from(const CL_HSMqk &C) {
            return CL_HSMqk(C);
        }

        /**@}*/

        /**
         * @name Public methods to retrieve the public parameters
         *@{
         */
        /** Return k */
        size_t k () const;
        /** Return q, the cardinality of the subgroup \f$F\f$ is \f$M=q^k\f$. */
        const Mpz & q () const;
        /** Return p, a odd prime or 1. */
        const Mpz & p () const;
        /** Return \f$M=q^{k}\f$, the conductor of \f$\Delta\f$. */
        const Mpz & M () const;
        /** Return \f$\Delta_K = -pq\f$. */
        const Mpz & DeltaK () const;
        /** Return \f$\Delta = -pq^{2k+1}\f$. */
        const Mpz & Delta () const;
        /**
         * Return \f$\ClDeltaK\f$: the class group of discriminant
         * \f$\Delta_K = -pq\f$.
         */
        const ClassGroup & Cl_DeltaK () const;
        /**
         * Return \f$\ClDelta\f$: the class group of discriminant
         * \f$\Delta = -pq^{2k+1}\f$.
         */
        const ClassGroup & Cl_Delta () const;
        const ClassGroup & Cl_G () const;
        /** Return \f$h\f$, the generator of the cyclic subgroup \f$H\f$ */
        const QFI & h () const;
        /** Return whether the compact variant is used or not */
        bool compact_variant () const;
        /** Return whether the large message variant is used or not */
        bool large_message_variant () const;
        /** Return the bound for secret keys: the bound on the size of \f$H\f$ */
        const Mpz & secretkey_bound () const;
        /** Return the bound for cleartexts: \f$M=q^k\f$ */
        const Mpz & cleartext_bound () const;
        /** Return the bound for random exponents: same as #secretkey_bound */
        const Mpz & encrypt_randomness_bound () const;
        /**@}*/

        /**
         * @name Public methods for computation in subgroups
         *@{
         */
        /** Set @p r to \f$h^e\f$, where #h is the generator of \f$H\f$. */
        void power_of_h (QFI &r, const Mpz &e) const;
        /** Return \f$f^m\f$, where `f` is the generator of \f$F\f$. */
        QFI power_of_f (const Mpz &m) const;
        /** Return the discrete logarithm of the form @p fm. */
        Mpz dlog_in_F (const QFI &fm) const;
        /**
         * Compute \f$\psi_{q^k}(f)\f$ to move @p f from \f$\Delta_K\f$ to
         * \f$\Delta\f$.
         */
        void from_Cl_DeltaK_to_Cl_Delta (QFI &f) const;
        /** Compute the genus of the form f */
        std::tuple<int, int> genus (const QFI &f) const;
        /**@}*/

        /**
         * @name Public methods implementing the cryptographic functionalities
         *@{
         */
        /** Generate a random secret key */
        SecretKey keygen (RandGen &randgen) const;
        /** Compute the public key associated to a secret key */
        PublicKey keygen (const SecretKey &sk) const;
        /** Encrypt @p m using public key @p pk */
        CipherText encrypt (const PublicKey &pk, const ClearText &m,
                            RandGen &randgen) const;
        /** Encrypt @p m using public key @p pk and randomness @p r*/
        CipherText encrypt (const PublicKey &pk, const ClearText &m,
                            const Mpz&r) const;
        /** Decrypt @p c using secret key @p sk*/
        ClearText decrypt (const SecretKey &sk, const CipherText &c) const;
        /** Homomorphically add ciphertexts @p ca and @p cb */
        CipherText add_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                    const CipherText &cb, RandGen &randgen) const;
        /** Homomorphically add ciphertexts @p ca and @p cb using @p r */
        CipherText add_ciphertexts (const PublicKey &pk, const CipherText &ca,
                                    const CipherText &cb, const Mpz &r) const;
        /** Add the two cleartexts @p ma and @p mb */
        ClearText add_cleartexts (const ClearText &ma, const ClearText &mb) const;
        /** Homomorphically compute @p s times @p c */
        CipherText scal_ciphertexts (const PublicKey &pk, const CipherText &c,
                                     const Mpz &s, RandGen &randgen) const;
        /** Homomorphically compute @p s times @p c using @p r*/
        CipherText scal_ciphertexts (const PublicKey &pk, const CipherText &c,
                                     const Mpz &s, const Mpz &r) const;
        /** Compute @p s times @p m */
        ClearText scal_cleartexts (const ClearText &m, const Mpz &s) const;
        /**@}*/

        /** Print the public parameters of the cryptosystem */
        friend std::ostream & operator<< (std::ostream &, const CL_HSMqk &);

    protected:
        /* utils for ctor */
        static Mpz random_p (RandGen &randgen, const Mpz &q, size_t DeltaK_nbits);
        static Mpz compute_DeltaK (const Mpz &, const Mpz &);
        static Mpz compute_Delta (const Mpz &, const Mpz &, size_t);
        /* utils */
        void raise_to_power_M (const ClassGroup &Cl, QFI &f) const;
        void F_kerphi_pow (Mpz &, const Mpz &, const Mpz &) const;
        size_t F_kerphi_div (Mpz &, const Mpz &, size_t, const Mpz &) const;
    };

    class CL_HSMqk_ZKAoK : protected CL_HSMqk
    {
    protected:
        size_t C_exp2_; /* Use 2^C_exp2_ as the bound in the ZK proof */
        mutable OpenSSL::HashAlgo H_;

    public:

        /* ctor */
        CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                        const Mpz &t);
        CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                        RandGen &randgen);
        CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, RandGen &randgen);

        class Proof
        {
        protected:
            Mpz u1_;
            Mpz u2_;
            Mpz k_;

        public:
            Proof (const CL_HSMqk_ZKAoK &C, const PublicKey &pk,
                   const CipherText &c, const ClearText &a, const Mpz &r,
                   RandGen &randgen);

            bool verify (const CL_HSMqk_ZKAoK &, const PublicKey &pk,
                         const CipherText &) const;

        protected:
            Mpz k_from_hash (const CL_HSMqk_ZKAoK &C, const PublicKey &pk,
                             const CipherText &c, const QFI &t1,
                             const QFI &t2) const;
        };

        /* */
        Proof noninteractive_proof (const PublicKey &pk, const CipherText &c,
                                    const ClearText &a, const Mpz &r,
                                    RandGen &randgen) const;
        bool noninteractive_verify (const PublicKey &pk, const CipherText &c,
                                    const Proof &proof) const;

        /* 重载方法，用于autocxx生成接口 */
        SecretKey keygen (RandGen &randgen) const {
            return CL_HSMqk::keygen(randgen);
        }
        PublicKey keygen (const SecretKey &sk) const {
            return CL_HSMqk::keygen(sk);
        }
        CipherText encrypt (const PublicKey &pk, const ClearText &m, RandGen &randgen) const {
            return CL_HSMqk::encrypt(pk, m, randgen);
        }
        CipherText encrypt (const PublicKey &pk, const ClearText &m, const Mpz&r) const {
            return CL_HSMqk::encrypt(pk, m, r);
        }
        ClearText decrypt (const SecretKey &sk, const CipherText &c) const {
            return CL_HSMqk::decrypt(sk, c);
        }
        const Mpz & encrypt_randomness_bound () const {
            return CL_HSMqk::encrypt_randomness_bound();
        }
    };


//  #include "CL_HSMqk.inl"
/**
 * The product \f$ p \times q \f$ must be \f$ 3 \bmod 4 \f$
 *
 * \param[in] q the prime q
 * \param[in] p the prime p or 1
 * \param[in] fud_factor positive integer to use as multiplier for the class
 * number bound
 * \param[in] compact_variant whether the compact variant is used
 *
 */
    inline
    CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p,
                        const Mpz &fud_factor, bool compact_variant)
            : q_(q),
              k_(k),
              p_(p),
              Cl_DeltaK_ (compute_DeltaK (q, p)),
              Cl_Delta_ (compute_Delta (Cl_DeltaK_.discriminant(), q, k_)),
              compact_variant_ (compact_variant),
              fud_factor_ (fud_factor)
    {
        /* Checks */
        if (q_.sgn() <= 0 || not q_.is_prime())
            throw std::invalid_argument ("q must be a prime");
        if (p_ != 1UL && (p_.sgn() <= 0 || not p_.is_prime()))
            throw std::invalid_argument ("p must be 1 or a prime");
        if ((- p_.mod4() * q_.mod4()) % 4 != 1)
            throw std::invalid_argument ("-p*q mod 4 must be 1");
        if (q_.kronecker (p_) != -1)
            throw std::invalid_argument ("Kronecker symbol of q and p must be -1");
        if (k_ == 0)
            throw std::invalid_argument ("k must be positive");

        /* Compute M = q^k */
        M_ = 1UL;
        for (size_t i = 0; i < k_; i++)
        {
            Mpz::mul (M_, M_, q_);
        }

        /* Assess if we need the large message variant, i.e., if 4*q^(2k) > 1-DeltaK
         */
        Mpz t;
        Mpz::mul (t, M_, M_);       /* t <- M^2 = q^(2*k) */
        Mpz::mulby4 (t, t);         /* t <- 4*q^(2*k) */
        Mpz::sub (t, t, 1UL);       /* t <- 4*q^(2*k) - 1 */
        Mpz::add (t, t, DeltaK());  /* t <- 4*q^(2*k) - 1 + DeltaK  */
        large_message_variant_ = (t.sgn() > 0);

        /* Compute the generator h
         * For the non compact variant, the generator is the square of the
         * smallest primeform of Cl_Delta raised to the power M=q^k.
         * For the compact variant, we push it into Cl_DeltaK and raise it to the
         * power M=q^k.
         */
        /* smallest primeform */
        Mpz l(2UL);
        for ( ; Delta().kronecker (l) != 1; l.nextprime ());
        h_ = Cl_Delta_.primeform (l);

        /* square it */
        Cl_Delta_.nudupl (h_, h_);

        /* raise it to power M=q^k */
        raise_to_power_M (Cl_Delta_, h_);

        if (compact_variant) /* For compact variant, we need \pi(h)^M */
        {
            h_.to_maximal_order (M_, DeltaK());
            raise_to_power_M (Cl_DeltaK_, h_);
        }

        /*
         * Compute the exponent_bound as class_number_bound times fud_factor.
         * If fud_factor is <= 0, the default it to use 2^40.
         */
        exponent_bound_ = Cl_DeltaK_.class_number_bound();
        if (fud_factor_.sgn () <= 0)
        {
            Mpz::mulby2k (exponent_bound_, exponent_bound_, 40);
            Mpz::mulby2k (fud_factor_, 1UL, 40);
        }
        else
            Mpz::mul (exponent_bound_, exponent_bound_, fud_factor_);

        /*
         * Precomputation
         */
        d_ = (encrypt_randomness_bound().nbits () + 1)/2;
        e_ = d_/2 + 1;
        h_de_precomp_ = h_;
        for (size_t i = 0; i < d_+e_; i++)
        {
            if (i == e_)
                h_e_precomp_ = h_de_precomp_;
            if (i == d_)
                h_d_precomp_ = h_de_precomp_;
            Cl_G().nudupl (h_de_precomp_, h_de_precomp_);
        }
    }

/**
 */
    inline
    CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p,
                        const Mpz &fud_factor)
            : CL_HSMqk (q, k, p, fud_factor, false)
    {
    }

/**
 */
    inline
    CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p, bool compact_variant)
            : CL_HSMqk (q, k, p, Mpz(0UL), compact_variant)
    {
    }

/**
 */
    inline
    CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, const Mpz &p)
            : CL_HSMqk (q, k, p, Mpz(0UL))
    {
    }

/**
 */
    inline
    CL_HSMqk::CL_HSMqk (const CL_HSMqk &C, bool compact_variant)
            : CL_HSMqk (C)
    {
        if (compact_variant != C.compact_variant_)
        {
            compact_variant_ = compact_variant;
            if (compact_variant)
            {
                /* we go from non compact to compact variant, we need to compute
                 * \pi(h)^M
                 */
                h_.to_maximal_order (M_, DeltaK());
                raise_to_power_M (Cl_DeltaK_, h_);
            }
            else
            {
                /* smallest primeform */
                Mpz l(2UL);
                for ( ; Delta().kronecker (l) != 1; l.nextprime ());
                h_ = Cl_Delta_.primeform (l);

                /* square it */
                Cl_Delta_.nudupl (h_, h_);

                /* raise it to power M=q^k */
                raise_to_power_M (Cl_Delta_, h_);
            }


            /* precomputations */
            h_de_precomp_ = h_;
            for (size_t i = 0; i < d_+e_; i++)
            {
                if (i == e_)
                    h_e_precomp_ = h_de_precomp_;
                if (i == d_)
                    h_d_precomp_ = h_de_precomp_;
                Cl_G().nudupl (h_de_precomp_, h_de_precomp_);
            }
        }
    }

/**
 * @private
 */
    inline
    CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, size_t DeltaK_nbits,
                        RandGen &randgen, const Mpz &fud_factor, bool compact_variant)
            : CL_HSMqk (q, k, CL_HSMqk::random_p (randgen, q, DeltaK_nbits), fud_factor, compact_variant)
    {
    }

/**
 * @private
 */
    inline
    CL_HSMqk::CL_HSMqk (size_t q_nbits, size_t k, size_t DeltaK_nbits,
                        RandGen &randgen, const Mpz &fud_factor, bool compact_variant)
            : CL_HSMqk (randgen.random_prime (q_nbits), k, DeltaK_nbits, randgen, fud_factor, compact_variant)
    {
    }

/**
 * @private
 */
    inline
    CL_HSMqk::CL_HSMqk (size_t q_nbits, size_t k, SecLevel seclevel,
                        RandGen &randgen, const Mpz &fud_factor, bool compact_variant)
            : CL_HSMqk (randgen.random_prime(q_nbits), k, seclevel, randgen, fud_factor, compact_variant)
    {
        if (q_nbits < seclevel)
            throw std::invalid_argument ("Number of bits of q should not be smaller "
                                         "than the security level");
    }

/**
 * @private
 */
    inline
    CL_HSMqk::CL_HSMqk (const Mpz &q, size_t k, SecLevel seclevel,
                        RandGen &randgen, const Mpz &fud_factor, bool compact_variant)
            : CL_HSMqk (q, k, seclevel.discriminant_bitsize(), randgen, fud_factor, compact_variant)
    {
        if (q.nbits() < seclevel)
            throw std::invalid_argument ("Number of bits of q should not be smaller "
                                         "than the security level");
    }

/* */
    inline
    const Mpz & CL_HSMqk::q () const
    {
        return q_;
    }

/* */
    inline
    size_t CL_HSMqk::k () const
    {
        return k_;
    }

/* */
    inline
    const Mpz & CL_HSMqk::p () const
    {
        return p_;
    }

/* */
    inline
    const Mpz & CL_HSMqk::M () const
    {
        return M_;
    }

/* */
    inline
    const ClassGroup & CL_HSMqk::Cl_DeltaK () const
    {
        return Cl_DeltaK_;
    }

/* */
    inline
    const ClassGroup & CL_HSMqk::Cl_Delta () const
    {
        return Cl_Delta_;
    }

/* */
    inline
    const ClassGroup & CL_HSMqk::Cl_G () const
    {
        return compact_variant_ ? Cl_DeltaK_ : Cl_Delta_;
    }

/* */
    inline
    const Mpz & CL_HSMqk::DeltaK () const
    {
        return Cl_DeltaK_.discriminant();
    }

/* */
    inline
    const Mpz & CL_HSMqk::Delta () const
    {
        return Cl_Delta_.discriminant();
    }

/* */
    inline
    const QFI & CL_HSMqk::h () const
    {
        return h_;
    }

/* */
    inline
    bool CL_HSMqk::compact_variant () const
    {
        return compact_variant_;
    }

/* */
    inline
    bool CL_HSMqk::large_message_variant () const
    {
        return large_message_variant_;
    }

/* */
    inline
    std::ostream & operator<< (std::ostream &o, const CL_HSMqk &C)
    {
        return o << "q = " << C.q() << " # " << C.q().nbits() << " bits" << std::endl
                 << "k = " << C.k() << std::endl
                 << "p = " << C.p() << " # " << C.p().nbits() << " bits" << std::endl
                 << "DeltaK = -p*q # " << C.DeltaK().nbits() << " bits" << std::endl
                 << "Delta = -p*q^(2*k+1) # " << C.Delta().nbits() << " bits" << std::endl
                 << "h = " << C.h() << std::endl
                 << "compact_variant = " << C.compact_variant() << std::endl
                 << "large_message_variant = " << C.large_message_variant()
                 << std::endl;
    }

/* */
    inline
    const Mpz & CL_HSMqk::secretkey_bound () const
    {
        return exponent_bound_;
    }

/* */
    inline
    const Mpz & CL_HSMqk::cleartext_bound () const
    {
        return M_;
    }

/* */
    inline
    const Mpz & CL_HSMqk::encrypt_randomness_bound () const
    {
        return exponent_bound_;
    }

/**
 * \param[out] r the quadratic form corresponding to #gen to the power of \p e
 * \param[in] e the exponent
 */
    inline
    void CL_HSMqk::power_of_h (QFI &r, const Mpz &n) const
    {
        Cl_G().nupow (r, h_, n, d_, e_, h_e_precomp_, h_d_precomp_,
                      h_de_precomp_);
    }

/*
 * Return f^m where f is the form [ q^(2k), q^k, .. ] of discriminant
 * -p*q^(2k+1).
 *
 * Input:
 *  m: integer
 *
 * - Case k == 1: for m != 0 modulo q, f^m is the form [ q^2, L(m)*q, ... ]
 * of discriminant -p*q^3 where L(m) is a odd representative of 1/m modulo q in
 * [-q, q].  This form is reduced if p > 4*q. For m == 0 modulo q,
 * f^m is the principal form [ 1, 1, (1+p*q^3)/4 ] of discriminant -p*q^3.
 * - Case k > 1:
 */
    inline
    QFI CL_HSMqk::power_of_f (const Mpz &m) const
    {
        if (k_ == 1)
        {
            /* Note: c is used as temporary variable to store L(m) */
            Mpz a, b, c;

            try
            {
                Mpz::mod_inverse (c, m, q_);
                if (c.is_even ())
                    Mpz::sub (c, c, q_);
                /*    [ q^2, Lm*q, ((Lm*q)^2-Delta_q)/(4*q^2) ]
                 * =  [ q^2, Lm*q, ((Lm*q)^2-q^2*Delta_K)/(4*q^2) ]
                 * =  [ q^2, Lm*q, (Lm^2-Delta_K)/4 ]
                 */
                Mpz::mul (a, q_, q_); /* a = q^2 */
                Mpz::mul (b, c, q_); /* b = Lm*q */
                Mpz::mul (c, c, c);
                Mpz::sub (c, c, DeltaK());
                Mpz::divby4 (c, c); /* c = (Lm^2-Delta_K)/4 */
                /* No need to check the form (a,b,c)
                 * But, for large_message variant, the form is not necessarily reduced.
                 */
                return QFI (a, b, c, true);
            }
            catch (Mpz::ModInverseException &e)
            {
                /* if m is not invertible, set the form to the principal form */
                return Cl_Delta_.one();
            }
        }
        else /* k_ > 1 */
        {
            Mpz n;
            Mpz::mod (n, m, M_); /* n = m % M=2^k */

            if (n.sgn() == 0) /* m == 0 mod 2^k */
            {
                return Cl_Delta_.one();
            }
            else /* m != 0 mod 2^k: compute Lucas chains U_n and V_n */
            {
                /* Lucas chains with P=1 and Q=(1-DeltaK)/4 (so D = P^2 - 4*Q = DeltaK)
                 * Computing U_n and V_n can be done by computing
                 *  (0  1)^n (U0)         (0  1)^n (V0)
                 *  (-Q P)   (U1)   and   (-Q P)   (V1)
                 * Note that U0 = 0, U1 = 1, V0 = 2 and V1 = P = 1.
                 */
                /* TODO maybe faster using direct formula with binomials for Un and Vn.
                 * Bench it to compare.
                 */
                Mpz m00(1UL), m01(0UL);
                Mpz m10(0UL), m11(1UL);
                Mpz minusQ, t0, t1, t2, t3;

                Mpz::sub (minusQ, DeltaK(), 1UL);
                Mpz::divby4 (minusQ, minusQ);

                for (size_t i = n.nbits(); i > 0; i--)
                {
                    /* square */
                    Mpz::mul (t0, m00, m00);
                    Mpz::addmul (t0, m01, m10);
                    Mpz::mod (t0, t0, M_);

                    Mpz::mul (t1, m00, m01);
                    Mpz::addmul (t1, m01, m11);
                    Mpz::mod (t1, t1, M_);

                    Mpz::mul (t2, m10, m00);
                    Mpz::addmul (t2, m11, m10);
                    Mpz::mod (t2, t2, M_);

                    Mpz::mul (t3, m10, m01);
                    Mpz::addmul (t3, m11, m11);
                    Mpz::mod (t3, t3, M_);

                    Mpz::swap (m00, t0);
                    Mpz::swap (m01, t1);
                    Mpz::swap (m10, t2);
                    Mpz::swap (m11, t3);

                    /* mul */
                    if (n.tstbit (i-1))
                    {
                        Mpz::mul (m00, m00, minusQ);
                        Mpz::add (m00, m00, m10);
                        Mpz::mod (m00, m00, M_);

                        Mpz::mul (m01, m01, minusQ);
                        Mpz::add (m01, m01, m11);
                        Mpz::mod (m01, m01, M_);

                        Mpz::swap (m00, m10);
                        Mpz::swap (m01, m11);
                    }
                }

                /* Vn = 2*m00+m01 */
                Mpz::add (t0, m00, m01);
                Mpz::add (t0, t0, m00);

                /* Un = m01, we need Un/q^(k-j) = Un/q^valq */
                const size_t valq = Mpz::remove (t1, m01, q_);

                t3 = 1UL;
                for (size_t i = 0; i < k_-valq; i++)
                {
                    Mpz::mul (t3, t3, q_);
                }
                /* now t3 = q^(k-valq) = q^j */
                Mpz::mod_inverse (t2, t1, t3); /* t2 <- (Un/q^(k-j))^1 mod q^j */

                Mpz::mul (t0, t0, t2);
                Mpz::mod (t0, t0, t3);
                if (t0.is_even()) /* if even, substract q^j */
                    Mpz::sub (t0, t0, t3);

                /* a <- q^(2*(k-valq)) = q^(2*j) = (q^j)^2    [ stored in t1 ] */
                Mpz::mul (t1, t3, t3);
                /* b <- q^(k-valq) * u  [ stored in t2 ] */
                Mpz::mul (t2, t0, t3);
                /* c <- (u^2 - q^(2*valq)*Delta_K)/4  [ stored in t3 ] */
                t3 = 1UL;
                for (size_t i = 0; i < valq; Mpz::mul (t3, t3, q_), i++);
                Mpz::mul (t3, t3, t3);        /* q^(2*valq) */
                Mpz::mul (t3, t3, DeltaK());  /* q^(2*valq) * Delta_K */
                Mpz::submul (t3, t0, t0);     /* q^(2*valq) * Delta_K - u^2 */
                t3.neg();
                Mpz::divby4 (t3, t3);

                /* No need to check the form (a,b,c) */
                return QFI (t1, t2, t3, true);
            }
        }
    }

/* Assume fm is in F */
    inline
    Mpz CL_HSMqk::dlog_in_F (const QFI &fm) const
    {
        Mpz m;
        if (!fm.is_one ())
        {
            Mpz tmp, tm;
            size_t tm_valq;
            /* tm = tm*q^tm_valq */

            if (large_message_variant_)
            {
                tm = fm.kernel_representative (M_, DeltaK());
                tm_valq = Mpz::remove (tm, tm, q_);
            }
            else
            {
                Mpz u;
                size_t j = Mpz::remove (u, fm.b(), q_); /* j, u such that ft.b = q^j*u */
                /* tm = q^(k-j)*1/u mod M=q^k */
                Mpz::mod_inverse (tm, u, M_);
                tm_valq = k_ - j;
            }

            if (k_ == 1) /* easy case */
            {
                m = tm;
            }
            else
            {
                Mpz mi, t(1UL), qe(1UL);

                for (size_t i = 0; i < k_; i++)
                {
                    if (tm_valq == i)
                    {
                        Mpz::mod (mi, tm, q_);
                        F_kerphi_pow (tmp, t, mi);
                        tm_valq = F_kerphi_div (tm, tm, tm_valq, tmp);
                    }
                    else
                    {
                        mi = 0UL;
                    }
                    Mpz::addmul (m, mi, qe);
                    Mpz::mul (qe, qe, q_);
                    F_kerphi_pow (t, t, q_);
                }
            }
        }
        /* else: m is already set to the correct value: 0 */
        return m;
    }

/* */
    inline
    void CL_HSMqk::from_Cl_DeltaK_to_Cl_Delta (QFI &f) const
    {
        f.lift (M_);
        raise_to_power_M (Cl_Delta_, f);
    }

/* */
    inline
    CL_HSMqk::SecretKey CL_HSMqk::keygen (RandGen &randgen) const
    {
        return CL_HSMqk::SecretKey (*this, randgen);
    }

/* */
    inline
    CL_HSMqk::PublicKey CL_HSMqk::keygen (const CL_HSMqk::SecretKey &sk) const
    {
        return PublicKey (*this, sk);
    }

/*
 * Encrypt the plaintext using the cryptosystems described by params, the
 * public key pk and the randomness r.
 *
 * Input:
 *  params: the parameters of the cryptosystems
 *  pk: the public key
 *  m: the plaintext to encrypt
 *  r: randomness
 */
    inline
    CL_HSMqk::CipherText CL_HSMqk::encrypt (const PublicKey &pk, const ClearText &m,
                                            const Mpz &r) const
    {
        return CL_HSMqk::CipherText (*this, pk, m, r);
    }


/*
 * Same as above but without the randomness
 */
    inline
    CL_HSMqk::CipherText CL_HSMqk::encrypt (const PublicKey &pk, const ClearText &m,
                                            RandGen &randgen) const
    {
//        return encrypt (pk, m, randgen.random_mpz (encrypt_randomness_bound()));
        return CL_HSMqk::CipherText (*this, pk, m, randgen.random_mpz (encrypt_randomness_bound()));
    }

/*
 * Decrypt the ciphertext c using the cryptosystems described by params and
 * the secret key sk
 *
 * Input:
 *  sk: the secret key
 *  c: the ciphertext
 */
    inline
    CL_HSMqk::ClearText CL_HSMqk::decrypt (const CL_HSMqk::SecretKey &sk, const CipherText &c)
    const
    {
        return ClearText (*this, sk, c);
    }

/* */
    inline
    CL_HSMqk::CipherText CL_HSMqk::add_ciphertexts (const PublicKey &pk,
                                                    const CipherText &ca,
                                                    const CipherText &cb,
                                                    RandGen &randgen) const
    {
        Mpz r(randgen.random_mpz (encrypt_randomness_bound()));
        return add_ciphertexts (pk, ca, cb, r);
    }

/* */
    inline
    CL_HSMqk::CipherText CL_HSMqk::add_ciphertexts (const PublicKey &pk,
                                                    const CipherText &ca,
                                                    const CipherText &cb,
                                                    const Mpz &r) const
    {
        return CipherText (*this, pk, ca, cb, r);
    }

/* */
    inline
    CL_HSMqk::ClearText CL_HSMqk::add_cleartexts (const ClearText &ma,
                                                  const ClearText &mb) const
    {
        return ClearText (*this, ma, mb);
    }

/* */
    inline
    CL_HSMqk::CipherText CL_HSMqk::scal_ciphertexts (const PublicKey &pk,
                                                     const CipherText &c,
                                                     const Mpz &s,
                                                     RandGen &randgen) const
    {
        Mpz r(randgen.random_mpz (encrypt_randomness_bound()));
        return scal_ciphertexts (pk, c, s, r);
    }

/* */
    inline
    CL_HSMqk::CipherText CL_HSMqk::scal_ciphertexts (const PublicKey &pk,
                                                     const CipherText &c,
                                                     const Mpz &s,
                                                     const Mpz &r) const
    {
        return CipherText (*this, pk, c, s, r);
    }

/* */
    inline
    CL_HSMqk::ClearText CL_HSMqk::scal_cleartexts (const ClearText &m, const Mpz &s)
    const
    {
        return ClearText (*this, m, s);
    }

/*
 * Assumes q is a prime
 */
    inline
    Mpz CL_HSMqk::random_p (RandGen &randgen, const Mpz &q, size_t DeltaK_nbits)
    {
        Mpz p;

        /* The product -p*q must be 1 mod 4 (<=> p*q must be 3 mod 4)
         * As p and q are odd, it means that they must be different mod 4.
         */
        unsigned long pmod4_target = q.mod4() == 3UL ? 1UL : 3UL;

        size_t pbits = q.nbits() < DeltaK_nbits ? DeltaK_nbits - q.nbits() : 0;

        /* Generate a random prime p satisfying the conditions */
        if (pbits == 0)
            p = 1UL;
        else if (pbits == 1)
            p = 3UL;
        else
            p = randgen.random_prime (pbits);
        while (p.mod4() != pmod4_target || q.kronecker (p) != -1)
        {
            p.nextprime ();
        }

        return p;
    }

/* Compute DeltaK = -p*q
 */
    inline
    Mpz CL_HSMqk::compute_DeltaK (const Mpz &q, const Mpz &p)
    {
        Mpz d;
        Mpz::mul (d, p, q);
        d.neg ();
        return d;
    }

/* Compute Delta = q^(2*k) * DeltaK = -p*q^(2*k+1)
 */
    inline
    Mpz CL_HSMqk::compute_Delta (const Mpz &DeltaK, const Mpz &q, size_t k)
    {
        Mpz q2;
        Mpz::mul (q2, q, q);
        Mpz d(DeltaK);
        for (size_t i = 0; i < k; i++)
        {
            Mpz::mul (d, d, q2);
        }
        return d;
    }

/* */
    inline
    void CL_HSMqk::raise_to_power_M (const ClassGroup &Cl, QFI &f) const
    {
        Cl.nupow (f, f, M_);
    }

/*
 * Compute (1+t*sqrt(DeltaK))^n in (OK/q^k OK)* / (Z/q^k Z)*
 * Result is given as (1+r*sqrt(DeltaK))
 * Use double and add to perform exponentiation
 */
    inline
    void CL_HSMqk::F_kerphi_pow (Mpz &r, const Mpz &t, const Mpz &n) const
    {
        Mpz a(1UL), b(0UL), tmp;

        for (size_t i = n.nbits(); i > 0; i--)
        {
            /* square */
            Mpz::mul (tmp, a, b);
            Mpz::mulby2 (tmp, tmp);
            Mpz::mod (tmp, tmp, M_);

            Mpz::mul (a, a, a);
            Mpz::mul (b, b, b);
            Mpz::addmul (a, b, Cl_DeltaK_.discriminant());
            Mpz::mod (a, a, M_);

            Mpz::swap (tmp, b);

            /* mul */
            if (n.tstbit (i-1))
            {
                Mpz::mul (tmp, b, t);
                Mpz::addmul (b, a, t);
                Mpz::mod (b, b, M_);

                Mpz::addmul (a, tmp, Cl_DeltaK_.discriminant());
                Mpz::mod (a, a, M_);
            }
        }

        Mpz::mod_inverse (r, a, M_);
        Mpz::mul (r, r, b);
        Mpz::mod (r, r, M_);

    }

/*
 * Compute (1+t*q^v*sqrt(DeltaK))/(1+s*sqrt(DeltaK)) in
 *  (OK/q^k OK)* / (Z/q^k Z)*
 * Result is given as (1+r*q^(return value)*sqrt(DeltaK))
 */
    inline
    size_t CL_HSMqk::F_kerphi_div (Mpz &r, const Mpz &t, size_t v, const Mpz &s)
    const
    {
        Mpz tmp0, tmp1;

        Mpz::mul (tmp0, t, s);
        for (size_t i = 0; i < v; i++)
        {
            Mpz::mul (tmp0, tmp0, q_);
        }

        Mpz::mul (tmp0, tmp0, Cl_DeltaK_.discriminant());
        tmp0.neg();
        Mpz::add (tmp0, tmp0, 1UL);
        Mpz::mod_inverse (tmp0, tmp0, M_);

        size_t j = Mpz::remove (tmp1, s, q_);
        if (j < v)
        {
            r = t;
            for (size_t i = 0; i < v-j; i++)
            {
                Mpz::mul (r, r, q_);
            }
            Mpz::sub (r, r, tmp1);
        }
        else if (j > v)
        {
            for (size_t i = 0; i < j-v; i++)
            {
                Mpz::mul (tmp1, tmp1, q_);
            }
            Mpz::sub (r, r, tmp1);
            j = v;
        }
        else /* j == v */
        {
            Mpz::sub (r, t, tmp1);
            j = v + Mpz::remove (r, r, q_);
        }
        Mpz::mul (r, r, tmp0);
        Mpz::mod (r, r, M_);
        return j;
    }

/**
 *
 * Remark:
 *  - chi_p and chi_q can be computed using different evaluations
 *  - At least on of f(1,0) = a, f(0,1) = c and f(1,1) = a+b+c is coprime with p
 *  (resp. q). Note that the evaluation used to compute chi_p and chi_q could be
 *  different.
 */
    inline
    std::tuple<int, int> CL_HSMqk::genus (const QFI &f) const
    {
        int chi_q, chi_p;
        chi_q = f.a().jacobi (q_);
        if (chi_q == 0)
            chi_q = f.c().jacobi (q_);

        chi_p = f.a().jacobi (p_);
        if (chi_p == 0)
            chi_p = f.c().jacobi (p_);

        if (chi_p == 0 || chi_q == 0)
        {
            Mpz t;
            Mpz::add (t, f.a(), f.b());
            Mpz::add (t, t, f.c());
            if (chi_q == 0)
                chi_q = t.jacobi (q_);
            if (chi_p == 0)
                chi_p = t.jacobi (p_);
        }
        return { chi_q, chi_p };
    }

/* */
    template <>
    void OpenSSL::HashAlgo::hash_update (const CL_HSMqk::PublicKey &pk)
    {
        hash_update (pk.elt());
    }

/* */
    template <>
    void OpenSSL::HashAlgo::hash_update (const CL_HSMqk::CipherText &c)
    {
        hash_update (c.c1());
        hash_update (c.c2());
    }

/******************************************************************************/
/* */
    inline
    CL_HSMqk_ZKAoK::CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                                    const Mpz &t)
            : CL_HSMqk (cryptosystem), C_exp2_ (C_exp2), H_ (OpenSSL::HashAlgo::SHAKE128)
    {
        if (C_exp2_ >= M_.nbits())
            throw std::runtime_error ("the bound C=2^C_exp2 must be smaller than q^k");

        /* Set h_ to h_^t */
        Cl_G().nupow (h_, h_, t);
        /* Precomputation data must be computed again */
        h_de_precomp_ = h_;
        for (size_t i = 0; i < d_+e_; i++)
        {
            if (i == e_)
                h_e_precomp_ = h_de_precomp_;
            if (i == d_)
                h_d_precomp_ = h_de_precomp_;
            Cl_G().nudupl (h_de_precomp_, h_de_precomp_);
        }
    }

/* */
    inline
    CL_HSMqk_ZKAoK::CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, size_t C_exp2,
                                    RandGen &randgen)
            : CL_HSMqk_ZKAoK (cryptosystem, C_exp2, randgen.random_mpz (cryptosystem.secretkey_bound()))
    {
    }

/* */
    inline
    CL_HSMqk_ZKAoK::CL_HSMqk_ZKAoK (const CL_HSMqk &cryptosystem, RandGen &randgen)
            : CL_HSMqk_ZKAoK (cryptosystem, std::min (cryptosystem.q().nbits()-1, 128UL), randgen)
    {
    }

/* */
    inline
    CL_HSMqk_ZKAoK::Proof CL_HSMqk_ZKAoK::noninteractive_proof (const PublicKey &pk,
                                                                const CipherText &c,
                                                                const ClearText &a,
                                                                const Mpz &r,
                                                                RandGen &randgen)
    const
    {
        return Proof (*this, pk, c, a, r, randgen);
    }

/* */
    inline
    bool CL_HSMqk_ZKAoK::noninteractive_verify (const PublicKey &pk,
                                                const CipherText &c,
                                                const Proof &proof) const
    {
        return proof.verify (*this, pk, c);
    }

/* */
    CL_HSMqk_ZKAoK::Proof::Proof (const CL_HSMqk_ZKAoK &C, const PublicKey &pk,
                                  const CipherText &c, const ClearText &a,
                                  const Mpz &r, RandGen &randgen)
    {
        Mpz B (C.exponent_bound_);
        Mpz::mulby2k (B, B, C.C_exp2_);
        Mpz::mul (B, B, C.fud_factor_);

        Mpz r1 (randgen.random_mpz (B));
        Mpz r2 (randgen.random_mpz (C.M_));
        CipherText t (C.encrypt (pk, ClearText (C, r2), r1));

        /* Generate k using hash function */
        k_ = k_from_hash (C, pk, c, t.c1(), t.c2());

        Mpz::mul (u1_, k_, r);
        Mpz::add (u1_, u1_, r1);

        Mpz::mul (u2_, k_, a);
        Mpz::add (u2_, u2_, r2);
        Mpz::mod (u2_, u2_, C.M_);
    }

/* */
    bool CL_HSMqk_ZKAoK::Proof::verify (const CL_HSMqk_ZKAoK &C,
                                        const PublicKey &pk,
                                        const CipherText &c) const
    {
        bool ret = true;

        /* Check that pk is a form in G */
        ret &= pk.elt().discriminant() == C.Cl_G().discriminant();
        ret &= C.genus (pk.elt()) == std::tuple<int, int> ({ 1, 1 });

        /* Check that c1 is a form in G */
        ret &= c.c1().discriminant() == C.Cl_G().discriminant();
        ret &= C.genus (c.c1()) == std::tuple<int, int> ({ 1, 1 });

        /* Check that c2 */
        ret &= c.c2().discriminant() == C.Cl_Delta().discriminant();
        ret &= C.genus (c.c2()) == std::tuple<int, int> ({ 1, 1 });

        /* Check u1 bound */
        Mpz B (C.fud_factor_);
        Mpz::add (B, B, 1UL);
        Mpz::mulby2k (B, B, C.C_exp2_);
        Mpz::mul (B, B, C.exponent_bound_);
        ret &= (u1_.sgn() >= 0 && u1_ <= B);

        /* Check u2 bound */
        ret &= (u2_.sgn() >= 0 && u2_ < C.M_);

        /* cu = (gq^u1, pk^u1 f^u2) */
        CipherText cu (C.encrypt (pk, ClearText (C, u2_), u1_));

        /* ck = (c1^k, c2^k) */
        CipherText ck (C.scal_ciphertexts (pk, c, k_, Mpz (0UL)));

        QFI t1, t2;

        /* Using the equality gq^u1 == t1*c1^k to compute t1 */
        C.Cl_G().nucompinv (t1, cu.c1(), ck.c1());

        /* Using the equality pk^u1 f^u2 == t2*c2^k to compute t2 */
        C.Cl_Delta().nucompinv (t2, cu.c2(), ck.c2());

        /* Generate k using hash function and check that it matches */
        Mpz k (k_from_hash (C, pk, c, t1, t2));
        ret &= (k == k_);

        return ret;
    }

/* */
    inline
    Mpz CL_HSMqk_ZKAoK::Proof::k_from_hash (const CL_HSMqk_ZKAoK &C,
                                            const PublicKey &pk,
                                            const CipherText &c,
                                            const QFI &t1, const QFI &t2) const
    {
        return Mpz (C.H_ (pk, c, t1, t2), C.C_exp2_);
    }

}

//#include "bicycl/seclevel.inl"
namespace BICYCL
{

/* */
    inline
    const std::vector<SecLevel> SecLevel::All ()
    {
        return { _112, _128, _192, _256 };
    }

/* */
    inline
    SecLevel::SecLevel (unsigned int s)
    {
        switch(s)
        {
            case 112 : value_ = _112; break;
            case 128 : value_ = _128; break;
            case 192 : value_ = _192; break;
            case 256 : value_ = _256; break;
            default  : throw InvalidSecLevelException() ; break;
        }
    }

/* */
    inline
    SecLevel::SecLevel (const std::string &s)
    {
        if (s == "112")       value_ = _112;
        else if (s == "128")  value_ = _128;
        else if (s == "192")  value_ = _192;
        else if (s == "256")  value_ = _256;
        else                  throw InvalidSecLevelException();
    }

/* */
    inline
    size_t SecLevel::RSA_modulus_bitsize () const
    {
        if (value_ == _112)        return 2048;
        else if (value_ == _128)   return 3072;
        else if (value_ == _192)   return 7680;
        else if (value_ == _256)   return 15360;
        else                       throw InvalidSecLevelException();
    }

/* */
    inline
    size_t SecLevel::discriminant_bitsize () const
    {
        if (value_ == _112)        return 1348;
        else if (value_ == _128)   return 1827;
        else if (value_ == _192)   return 3598;
        else if (value_ == _256)   return 5971;
        else                       throw InvalidSecLevelException();
    }

/* */
    inline
    int SecLevel::elliptic_curve_openssl_nid () const
    {
        if (value_ == _112)        return OpenSSL::ECGroup::P224;
        else if (value_ == _128)   return OpenSSL::ECGroup::P256;
        else if (value_ == _192)   return OpenSSL::ECGroup::P384;
        else if (value_ == _256)   return OpenSSL::ECGroup::P521;
        else                       throw InvalidSecLevelException();
    }

/* */
    inline
    int SecLevel::sha3_openssl_nid () const
    {
        if (value_ == _112)        return OpenSSL::HashAlgo::SHA3_224;
        else if (value_ == _128)   return OpenSSL::HashAlgo::SHA3_256;
        else if (value_ == _192)   return OpenSSL::HashAlgo::SHA3_384;
        else if (value_ == _256)   return OpenSSL::HashAlgo::SHA3_512;
        else                       throw InvalidSecLevelException();
    }

/* */
    inline
    std::ostream & operator<< (std::ostream &o, SecLevel seclevel)
    {
        return o << static_cast<unsigned int>(seclevel.value_);
    }

/* */
    inline
    std::string to_string (SecLevel seclevel)
    {
        return std::to_string (static_cast<unsigned int>(seclevel.value_));
    }
}

