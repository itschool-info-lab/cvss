/* Copyright (c) 2015-2019, Chandan B.N.
 *
 * Copyright (c) 2019, FIRST.ORG, INC
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 * following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
 *    following disclaimer in the documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
 *    products derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*

CVSSjs Version 0.1 beta

Usage:
    craete an html element with an id for eg.,
    <div id="cvssboard"></div>

    // create a new instance of CVSS calculator:
    var c = new CVSS("cvssboard");

    // create a new instance of CVSS calculator with some event handler callbacks
    var c = new CVSS("cvssboard", {
                onchange: function() {....} //optional
                onsubmit: function() {....} //optional
                }
                
    // set a vector
    c.set('AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L');
    
    //get the value
    c.get() returns an object like:

    {
        score: 4.3,
        vector: 'AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L'
    }
    
*/

var CVSS = function (id, options) {
    this.options = options;
    this.wId = id;
    var e = function (tag) {
        return document.createElement(tag);
    };

    // Base Group
    this.bg = {
        AV: 'Attack Vector',
        AC: 'Attack Complexity',
        PR: 'Privileges Required',
        UI: 'User Interaction',
        S: 'Scope',
        C: 'Confidentiality',
        I: 'Integrity',
        A: 'Availability'
    };

    // Base Metrics
    this.bm = {
        AV: {
            N: {
                l: 'Network',
                d: "<b style=\"color:red;\">최악:</b></font> 취약한 구성 요소는 네트워크 스택에 바인딩되며, 가능한 공격자 집합은 아래 나열된 다른 옵션 이상으로 확장되며, 전체 인터넷까지 포함한다.그러한 취약성은 종종 \"원격적으로 이용 가능한\" 것으로 불리며, 프로토콜 수준에서 하나 이상의 네트워크 홉(예: 하나 이상의 라우터에 걸쳐)에서 공격이 이용 가능한 것으로 생각할 수 있다."
            },
            A: {
                l: 'Adjacent',
                d: "<b style=\"color:red;\">최악:</b> 취약한 구성 요소는 네트워크 스택에 바인딩되지만 공격은 프로토콜 수준에서 논리적으로 인접한 토폴로지로 제한됩니다. 이는 공격이 동일한 공유 물리적(예: Bluetooth 또는 IEEE 802.11) 또는 논리적(예: 로컬 IP 서브넷) 네트워크 또는 보안 또는 기타 제한된 행정 도메인(예: MPLS, 관리 네트워크 구역으로 VPN을 보안) 내에서 시작되어야 한다는 것을 의미할 수 있다.인접 공격의 한 예는 ARP(IPv4) 또는 이웃 발견(IPv6) 홍수로 인해 로컬 LAN 세그먼트에서 서비스 거부로 이어질 수 있다."
            },
            L: {
                l: 'Local',
                d: "<b style=\"color:yellow;\">나쁨:</b> 취약한 구성 요소는 네트워크 스택에 바인딩되지 않으며 공격자의 경로는 읽기 / 쓰기 / 실행 기능을 통해 수행됩니다.<ul><li>공격자는 대상 시스템(예: 키보드, 콘솔) 또는 원격으로(예: SSH)에 액세스하여 취약성을 악용한다.</li><li>공격자는 다른 사람이 취약성을 이용하기 위해 필요한 작업을 수행하기 위해 사용자 상호작용에 의존한다(예: 소셜 엔지니어링 기술을 사용하여 합법적인 사용자가 악의적인 문서를 열도록 속인다).</li></ul>"
            },
            P: {
                l: 'Physical',
                d: "<b style=\"color:yellow;\">나쁨:</b> 공격은 공격자가 취약한 구성요소를 물리적으로 만지거나 조작하도록 요구합니다. 신체적 상호작용은 짧거나(예: 사악한 하녀 공격) 지속적일 수 있다. 이러한 공격의 예는 공격자가 대상 시스템에 물리적으로 액세스한 후 디스크 암호화 키에 액세스할 수 있는 콜드 부트 공격입니다.다른 예로는 FireWire/USB Direct Memory Access(DMA)를 통한 주변 공격이 있다."
            }
        },
        AC: {
            L: {
                l: 'Low',
                d: "<b style=\"color:red;\">최악:</b> 특수 액세스 조건 또는 불가피한 상황이 존재하지 않습니다.공격자는 취약한 구성요소를 공격할 때 반복 가능한 성공을 기대할 수 있습니다."
            },
            H: {
                l: 'High',
                d: "<b style=\"color:yellow;\">나쁨:</b> 공격이 성공하려면 공격자가 통제할 수 없는 조건이 필요합니다.즉, 성공적인 공격은 마음대로 수행할 수 없지만 공격자는 성공적인 공격을 예상하기 전에 취약한 구성 요소에 대한 준비 또는 실행에 측정 가능한 노력에 투자해야 합니다."
            }
        },
        PR: {
            N: {
                l: 'None',
                d: "<b style=\"color:red;\">최악:</b> 공격자는 공격 전에 허가되지 않으므로 공격을 수행하기 위해 취약한 시스템의 설정이나 파일에 대한 액세스가 필요하지 않습니다."
            },
            L: {
                l: 'Low',
                d: "<b style=\"color:red;\">최악:</b> 공격자는 일반적으로 사용자가 소유한 설정 및 파일에만 영향을 미칠 수 있는 기본 사용자 기능을 제공하는 권한을 요구합니다.또는 권한이 낮은 공격자는 비민감적인 리소스에만 액세스할 수 있습니다."
            },
            H: {
                l: 'High',
                d: "<b style=\"color:yellow;\">나쁨:</b> 공격자는 취약한 구성요소에 대한 상당한(예를 들어, 관리) 제어를 제공하는 권한이 필요하므로 구성요소 전체 설정 및 파일에 액세스할 수 있습니다."
            }
        },
        UI: {
            N: {
                l: 'None',
                d: "<b style=\"color:red;\">최악:</b> 취약한 시스템은 사용자로부터의 상호 작용 없이 이용될 수 있다."
            },
            R: {
                l: 'Required',
                d: "<b style=\"color:yellow;\">나쁨:</b> 이 취약성에 대한 공격이 성공하려면 취약성을 이용하기 전에 사용자가 일부 작업을 수행해야 합니다.예를 들어, 시스템 관리자가 응용프로그램을 설치하는 동안만 공격이 성공할 수 있습니다."
            }
        },

        S: {
            C: {
                l: 'Changed',
                d: "<b style=\"color:red;\">최악:</b> 공격된 취약성은 취약한 구성요소의 보안 권한이 관리하는 보안 범위를 넘어 리소스에 영향을 미칠 수 있습니다.이 경우 취약한 구성 요소와 영향을 받는 구성 요소는 서로 다르며 다른 보안 당국에 의해 관리됩니다."
            },
            U: {
                l: 'Unchanged',
                d: "<b style=\"color:yellow;\">나쁨:</b> 공격된 취약성은 동일한 보안 당국이 관리하는 리소스에만 영향을 미칠 수 있습니다.이 경우 취약한 구성 요소와 영향을 받는 구성 요소는 동일하거나 둘 다 동일한 보안 당국에 의해 관리됩니다."
            }
        },
        C: {
            H: {
                l: 'High',
                d: "<b style=\"color:red;\">최악:</b> 기밀성이 완전히 상실되어 영향을 받은 구성요소 내의 모든 리소스가 공격자에게 누설된다. 또는 일부 제한 정보만 액세스할 수 있지만 공개된 정보는 직접적이고 심각한 영향을 미칩니다.예를 들어, 공격자는 관리자의 암호 또는 웹 서버의 개인 암호화 키를 훔칩니다."
            },
            L: {
                l: 'Low',
                d: "<b style=\"color:yellow;\">나쁨:</b> 기밀성 상실이 있다. 일부 제한된 정보에 대한 액세스가 획득되지만 공격자는 어떤 정보를 얻는지 제어하지 못하거나 손실의 양이나 종류가 제한됩니다.정보 공개는 영향을 받는 구성요소에 직접적이고 심각한 손실을 초래하지 않습니다."
            },
            N: {
                l: 'None',
                d: "<b style=\"color:green;\">좋음:</b> 영향을 받은 구성요소 내에서 기밀성 손실은 없습니다."
            }
        },
        I: {
            H: {
                l: 'High',
                d: "<b style=\"color:red;\">최악:</b> 완전한 청렴함의 상실이나 완전한 보호 상실이 있다. 예를 들어 공격자는 영향을 받는 구성요소에 의해 보호되는 모든 파일 또는 모든 파일을 수정할 수 있습니다.또는 일부 파일만 수정할 수 있지만 악의적인 수정은 영향을 받는 구성 요소에 직접적이고 심각한 결과를 초래합니다."
            },
            L: {
                l: 'Low',
                d: "<b style=\"color:yellow;\">나쁨:</b> 데이터 수정은 가능하지만 공격자는 수정 결과를 제어하지 못하거나 수정 양이 제한되어 있습니다.데이터 수정은 영향을 받는 구성요소에 직접적이고 심각한 영향을 미치지 않습니다."
            },
            N: {
                l: 'None',
                d: "<b style=\"color:green;\">좋음:</b> 충격된 구성요소 내에 무결성의 손실이 없습니다."
            }
        },
        A: {
            H: {
                l: 'High',
                d: "<b style=\"color:red;\">최악:</b> 가용성의 총 손실이 있어 공격자는 영향을 받은 구성 요소의 자원에 대한 액세스를 완전히 거부할 수 있다. 이 손실은 지속되거나(공격자가 공격을 계속 전달하는 동안) 지속된다(공격이 완료된 후에도 상태가 지속된다).대안적으로, 공격자는 일부 가용성을 부정할 수 있는 능력을 가지고 있지만, 가용성의 손실은 영향을 받는 구성 요소에 직접적이고 심각한 결과를 초래한다(예: 공격자는 기존 연결을 방해할 수 없지만 새로운 연결을 예방할 수 있다; 공격자는 성공적인 공격의 각 경우, 적은 양의 메모리만 유출할 수 있는 취약성을 반복적으로 이용할 수 있지만, 반복적인 공격 후에는 서비스를 완전히 사용할 수 없게 된다)."
            },
            L: {
                l: 'Low',
                d: "<b style=\"color:yellow;\">나쁨:</b> 성능이 저하되거나 리소스 가용성이 중단됩니다. 취약성에 대한 반복적인 공격이 가능하더라도 공격자는 합법적인 사용자에 대한 서비스를 완전히 거부할 수 있는 기능을 가지고 있지 않습니다.영향을 받는 구성 요소의 리소스는 항상 부분적으로 사용 가능하거나 일부 시간만 완전히 사용 가능하지만 전반적으로 영향을 받는 구성 요소에 직접적이고 심각한 결과는 없습니다."
            },
            N: {
                l: 'None',
                d: "<b style=\"color:green;\">좋음:</b> 영향을 받은 구성요소 내에서 가용성에 영향을 미치지 않습니다."
            }
        }
    };
    
    this.bme = {};
    this.bmgReg = {
        AV: 'NALP',
        AC: 'LH',
        PR: 'NLH',
        UI: 'NR',
        S: 'CU',
        C: 'HLN',
        I: 'HLN',
        A: 'HLN'
    };
    this.bmoReg = {
        AV: 'NALP',
        AC: 'LH',
        C: 'C',
        I: 'C',
        A: 'C'
    };
    var s, f, dl, g, dd, l;
    this.el = document.getElementById(id);
    this.el.appendChild(s = e('style'));
    s.innerHTML = '';
    this.el.appendChild(f = e('form'));
    f.className = 'cvssjs';
    this.calc = f;
    for (g in this.bg) {
        f.appendChild(dl = e('dl'));
        dl.setAttribute('class', g);
        var dt = e('dt');
        dt.innerHTML = this.bg[g];
        dl.appendChild(dt);
        for (s in this.bm[g]) {
            dd = e('dd');
            dl.appendChild(dd);
            var inp = e('input');
            inp.setAttribute('name', g);
            inp.setAttribute('value', s);
            inp.setAttribute('id', id + g + s);
            inp.setAttribute('class', g + s);
            //inp.setAttribute('ontouchstart', '');
            inp.setAttribute('type', 'radio');
            this.bme[g + s] = inp;
            var me = this;
            inp.onchange = function () {
                me.setMetric(this);
            };
            dd.appendChild(inp);
            l = e('label');
            dd.appendChild(l);
            l.setAttribute('for', id + g + s);
            l.appendChild(e('i')).setAttribute('class', g + s);
            l.appendChild(document.createTextNode(this.bm[g][s].l + ' '));
            dd.appendChild(e('small')).innerHTML = this.bm[g][s].d;
        }
    }
    //f.appendChild(e('hr'));
    f.appendChild(dl = e('dl'));
    dl.innerHTML = '<dt>Severity&sdot;Score&sdot;Vector</dt>';
    dd = e('dd');
    dl.appendChild(dd);
    l = dd.appendChild(e('label'));
    l.className = 'results';
    l.appendChild(this.severity = e('span'));
    this.severity.className = 'severity';
    l.appendChild(this.score = e('span'));
    this.score.className = 'score';
    l.appendChild(document.createTextNode(' '));
    l.appendChild(this.vector = e('a'));
    this.vector.className = 'vector';
    this.vector.innerHTML = 'CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    
    if (options.onsubmit) {
        f.appendChild(e('hr'));
        this.submitButton = f.appendChild(e('input'));
        this.submitButton.setAttribute('type', 'submit');
        this.submitButton.onclick = options.onsubmit;
    }
};

CVSS.prototype.severityRatings = [{
    name: "None",
    bottom: 0.0,
    top: 0.0
}, {
    name: "Low",
    bottom: 0.1,
    top: 3.9
}, {
    name: "Medium",
    bottom: 4.0,
    top: 6.9
}, {
    name: "High",
    bottom: 7.0,
    top: 8.9
}, {
    name: "Critical",
    bottom: 9.0,
    top: 10.0
}];

CVSS.prototype.severityRating = function (score) {
    var i;
    var severityRatingLength = this.severityRatings.length;
    for (i = 0; i < severityRatingLength; i++) {
        if (score >= this.severityRatings[i].bottom && score <= this.severityRatings[i].top) {
            return this.severityRatings[i];
        }
    }
    return {
        name: "?",
        bottom: 'Not',
        top: 'defined'
    };
};

CVSS.prototype.valueofradio = function(e) {
    for(var i = 0; i < e.length; i++) {
        if (e[i].checked) {
            return e[i].value;
        }
    }
    return null;
};

CVSS.prototype.calculate = function () {
    var cvssVersion = "3.1";
    var exploitabilityCoefficient = 8.22;
    var scopeCoefficient = 1.08;

    // Define associative arrays mapping each metric value to the constant used in the CVSS scoring formula.
    var Weight = {
        AV: {
            N: 0.85,
            A: 0.62,
            L: 0.55,
            P: 0.2
        },
        AC: {
            H: 0.44,
            L: 0.77
        },
        PR: {
            U: {
                N: 0.85,
                L: 0.62,
                H: 0.27
            },
            // These values are used if Scope is Unchanged
            C: {
                N: 0.85,
                L: 0.68,
                H: 0.5
            }
        },
        // These values are used if Scope is Changed
        UI: {
            N: 0.85,
            R: 0.62
        },
        S: {
            U: 6.42,
            C: 7.52
        },
        C: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        I: {
            N: 0,
            L: 0.22,
            H: 0.56
        },
        A: {
            N: 0,
            L: 0.22,
            H: 0.56
        }
        // C, I and A have the same weights

    };

    var p;
    var val = {}, metricWeight = {};
    try {
        for (p in this.bg) {
            val[p] = this.valueofradio(this.calc.elements[p]);
            if (typeof val[p] === "undefined" || val[p] === null) {
                return "?";
            }
            metricWeight[p] = Weight[p][val[p]];
        }
    } catch (err) {
        return err; // TODO: need to catch and return sensible error value & do a better job of specifying *which* parm is at fault.
    }
    metricWeight.PR = Weight.PR[val.S][val.PR];
    //
    // CALCULATE THE CVSS BASE SCORE
    //
    var roundUp1 = function Roundup(input) {
        var int_input = Math.round(input * 100000);
        if (int_input % 10000 === 0) {
            return int_input / 100000
        } else {
            return (Math.floor(int_input / 10000) + 1) / 10
        }
    };
    try {
    var baseScore, impactSubScore, impact, exploitability;
    var impactSubScoreMultiplier = (1 - ((1 - metricWeight.C) * (1 - metricWeight.I) * (1 - metricWeight.A)));
    if (val.S === 'U') {
        impactSubScore = metricWeight.S * impactSubScoreMultiplier;
    } else {
        impactSubScore = metricWeight.S * (impactSubScoreMultiplier - 0.029) - 3.25 * Math.pow(impactSubScoreMultiplier - 0.02, 15);
    }
    var exploitabalitySubScore = exploitabilityCoefficient * metricWeight.AV * metricWeight.AC * metricWeight.PR * metricWeight.UI;
    if (impactSubScore <= 0) {
        baseScore = 0;
    } else {
        if (val.S === 'U') {
            baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore), 10));
        } else {
            baseScore = roundUp1(Math.min((exploitabalitySubScore + impactSubScore) * scopeCoefficient, 10));
        }
    }

    return baseScore.toFixed(1);
    } catch (err) {
        return err;
    }
};

CVSS.prototype.get = function() {
    return {
        score: this.score.innerHTML,
        vector: this.vector.innerHTML
    };
};

CVSS.prototype.setMetric = function(a) {
    var vectorString = this.vector.innerHTML;
    if (/AV:.\/AC:.\/PR:.\/UI:.\/S:.\/C:.\/I:.\/A:./.test(vectorString)) {} else {
        vectorString = 'AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_';
    }
    //e("E" + a.id).checked = true;
    var newVec = vectorString.replace(new RegExp('\\b' + a.name + ':.'), a.name + ':' + a.value);
    this.set(newVec);
};

CVSS.prototype.set = function(vec) {
    var newVec = 'CVSS:3.1/';
    var sep = '';
    for (var m in this.bm) {
        var match = (new RegExp('\\b(' + m + ':[' + this.bmgReg[m] + '])')).exec(vec);
        if (match !== null) {
            var check = match[0].replace(':', '');
            this.bme[check].checked = true;
            newVec = newVec + sep + match[0];
        } else if ((m in {C:'', I:'', A:''}) && (match = (new RegExp('\\b(' + m + ':C)')).exec(vec)) !== null) {
            // compatibility with v2 only for CIA:C
            this.bme[m + 'H'].checked = true;
            newVec = newVec + sep + m + ':H';
        } else {
            newVec = newVec + sep + m + ':_';
            for (var j in this.bm[m]) {
                this.bme[m + j].checked = false;
            }
        }
        sep = '/';
    }
    this.update(newVec);
};

CVSS.prototype.update = function(newVec) {
    this.vector.innerHTML = newVec;
    var s = this.calculate();
    this.score.innerHTML = s;
    var rating = this.severityRating(s);
    this.severity.className = rating.name + ' severity';
    this.severity.innerHTML = rating.name + '<sub>' + rating.bottom + ' - ' + rating.top + '</sub>';
    this.severity.title = rating.bottom + ' - ' + rating.top;
    if (this.options !== undefined && this.options.onchange !== undefined) {
        this.options.onchange();
    }
};
