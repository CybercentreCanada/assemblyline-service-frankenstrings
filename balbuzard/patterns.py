"""
Modified version of patterns.py found here:
https://github.com/decalage2/balbuzard

Info:
balbuzard patterns - v0.07 2014-02-13 Philippe Lagadec
For more info and updates: http://www.decalage.info/balbuzard
"""

# LICENSE:
#
# balbuzard is copyright (c) 2007-2014, Philippe Lagadec (http://www.decalage.info)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#  * Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import re
from al_services.alsvc_frankenstrings.balbuzard.balbuzard import Pattern, Pattern_re
from xml.etree import ElementTree

class PatternMatch:

    def __init__(self):
        # TLDs registered at IANA:
        #from http://data.iana.org/TLD/tlds-alpha-by-domain.txt
        # Version 2016070500, Last Updated Tue Jul  5 07:07:01 2016 UTC
        self.tlds = set(('aarp', 'abbott', 'abbvie', 'able', 'abogado', 'abudhabi', 'ac', 'academy',
                         'accenture', 'accountant', 'accountants', 'aco', 'active', 'actor', 'ad', 'adac', 'ads',
                         'adult', 'ae', 'aeg', 'aero', 'aetna', 'af', 'afl', 'ag', 'agakhan', 'agency', 'ai', 'aig',
                         'airbus', 'airforce', 'airtel', 'akdn', 'al', 'alibaba', 'alipay', 'allfinanz', 'ally',
                         'alsace', 'alstom', 'am', 'amica', 'amsterdam', 'analytics', 'android', 'anquan', 'anz', 'ao',
                         'apartments', 'app', 'apple', 'aq', 'aquarelle', 'ar', 'aramco', 'archi', 'army', 'arpa',
                         'art', 'arte', 'as', 'asia', 'associates', 'at', 'attorney', 'au', 'auction', 'audi',
                         'audible', 'audio', 'author', 'auto', 'autos', 'avianca', 'aw', 'aws', 'ax', 'axa', 'az',
                         'azure', 'ba', 'baby', 'baidu', 'band', 'bank', 'bar', 'barcelona', 'barclaycard', 'barclays',
                         'barefoot', 'bargains', 'bauhaus', 'bayern', 'bbc', 'bbva', 'bcg', 'bcn', 'bd', 'be',
                         'beats', 'beer', 'bentley', 'berlin', 'best', 'bet', 'bf', 'bg', 'bh', 'bharti', 'bi', 'bible',
                         'bid', 'bike', 'bing', 'bingo', 'bio', 'biz', 'bj', 'black', 'blackfriday', 'blanco', 'blog',
                         'bloomberg', 'blue', 'bm', 'bms', 'bmw', 'bn', 'bnl', 'bnpparibas', 'bo', 'boats',
                         'boehringer', 'bom', 'bond', 'boo', 'book', 'boots', 'bosch', 'bostik', 'bot', 'boutique',
                         'br', 'bradesco', 'bridgestone', 'broadway', 'broker', 'brother', 'brussels', 'bs', 'bt',
                         'budapest', 'bugatti', 'build', 'builders', 'business', 'buy', 'buzz', 'bv', 'bw', 'by', 'bz',
                         'bzh', 'ca', 'cab', 'cafe', 'cal', 'call', 'cam', 'camera', 'camp', 'cancerresearch', 'canon',
                         'capetown', 'capital', 'car', 'caravan', 'cards', 'care', 'career', 'careers', 'cars',
                         'cartier', 'casa', 'cash', 'casino', 'cat', 'catering', 'cba', 'cbn', 'cbre',
                         'ceb', 'center', 'ceo', 'cern', 'cf', 'cfa', 'cfd', 'cg', 'ch', 'chanel', 'channel', 'chase',
                         'chat', 'cheap', 'chintai', 'chloe', 'christmas', 'chrome', 'church', 'ci', 'cipriani',
                         'circle', 'cisco', 'citic', 'city', 'cityeats', 'ck', 'cl', 'claims', 'cleaning', 'click',
                         'clinic', 'clinique', 'clothing', 'cloud', 'club', 'clubmed', 'cm', 'cn', 'co', 'coach',
                         'codes', 'coffee', 'college', 'cologne', 'com', 'commbank', 'community', 'company', 'compare',
                         'computer', 'comsec', 'condos', 'construction', 'consulting', 'contact', 'contractors',
                         'cooking', 'cookingchannel', 'cool', 'coop', 'corsica', 'country', 'coupon', 'coupons',
                         'courses', 'cr', 'credit', 'creditcard', 'creditunion', 'cricket', 'crown', 'crs', 'cruises',
                         'csc', 'cu', 'cuisinella', 'cv', 'cw', 'cx', 'cy', 'cymru', 'cyou', 'cz', 'dabur', 'dad',
                         'dance', 'date', 'dating', 'datsun', 'day', 'dclk', 'dds', 'de', 'deal', 'dealer', 'deals',
                         'degree', 'delivery', 'dell', 'deloitte', 'delta', 'democrat', 'dental', 'dentist', 'desi',
                         'dev', 'dhl', 'diamonds', 'diet', 'digital', 'direct', 'directory', 'discount',
                         'dj', 'dk', 'dm', 'dnp', 'do', 'docs', 'dog', 'doha', 'domains', 'download', 'drive',
                         'dtv', 'dubai', 'dunlop', 'dupont', 'durban', 'dvag', 'dz', 'earth', 'eat', 'ec', 'edeka',
                         'edu', 'education', 'email', 'emerck', 'energy', 'engineer', 'engineering',
                         'enterprises', 'epost', 'epson', 'equipment', 'er', 'ericsson', 'erni', 'es', 'esq', 'estate',
                         'et', 'eu', 'eurovision', 'eus', 'everbank', 'exchange', 'expert', 'exposed',
                         'express', 'extraspace', 'fage', 'fail', 'fairwinds', 'faith', 'family', 'fan', 'fans',
                         'farm', 'farmers', 'fashion', 'fast', 'fedex', 'feedback', 'ferrero', 'fi', 'film', 'final',
                         'finance', 'financial', 'fire', 'firestone', 'firmdale', 'fish', 'fishing', 'fit', 'fitness',
                         'fj', 'fk', 'flickr', 'flights', 'flir', 'florist', 'flowers', 'flsmidth', 'fly', 'fm', 'fo',
                         'foo', 'foodnetwork', 'football', 'ford', 'forex', 'forsale', 'forum', 'foundation', 'fox',
                         'fr', 'fresenius', 'frl', 'frogans', 'frontdoor', 'frontier', 'ftr', 'fund', 'furniture',
                         'futbol', 'fyi', 'ga', 'gal', 'gallery', 'gallo', 'gallup', 'game', 'games', 'garden', 'gb',
                         'gbiz', 'gd', 'gdn', 'ge', 'gea', 'gent', 'genting', 'gift',
                         'gifts', 'gives', 'giving', 'gl', 'glass', 'gle', 'global', 'globo', 'gm', 'gmail', 'gmbh',
                         'gmo', 'gmx', 'gn', 'gold', 'goldpoint', 'golf', 'goodyear', 'goog', 'google', 'gop',
                         'got', 'gov', 'gp', 'gq', 'gr', 'grainger', 'gratis', 'green', 'gripe', 'group',
                         'gs', 'gt', 'gu', 'guardian', 'gucci', 'guge', 'guide', 'guitars', 'guru', 'gw', 'gy',
                         'hamburg', 'hangout', 'haus', 'hdfcbank', 'health', 'healthcare', 'help', 'helsinki', 'here',
                         'hermes', 'hgtv', 'hiphop', 'hisamitsu', 'hitachi', 'hiv', 'hk', 'hkt', 'hm', 'hn', 'hockey',
                         'holdings', 'holiday', 'homedepot', 'homes', 'honda', 'horse', 'host', 'hosting', 'hoteles',
                         'hotmail', 'house', 'how', 'hr', 'hsbc', 'ht', 'htc', 'hu', 'hyundai', 'ibm', 'icbc', 'ice',
                         'icu', 'ie', 'ifm', 'iinet', 'ikano', 'il', 'im', 'imamat', 'imdb', 'immo',
                         'immobilien', 'in', 'industries', 'infiniti', 'info', 'ing', 'ink', 'institute', 'insurance',
                         'insure', 'int', 'international', 'investments', 'io', 'ipiranga', 'iq', 'ir', 'irish', 'is',
                         'iselect', 'ismaili', 'ist', 'istanbul', 'it', 'itau', 'itv', 'iwc', 'jaguar', 'java', 'jcb',
                         'jcp', 'je', 'jetzt', 'jewelry', 'jlc', 'jll', 'jm', 'jmp', 'jnj', 'jo', 'jobs', 'joburg',
                         'jot', 'joy', 'jp', 'jpmorgan', 'jprs', 'juegos', 'kaufen', 'kddi', 'ke', 'kerryhotels',
                         'kerrylogistics', 'kerryproperties', 'kfh', 'kg', 'kh', 'ki', 'kia', 'kim', 'kinder', 'kindle',
                         'kitchen', 'kiwi', 'km', 'kn', 'koeln', 'komatsu', 'kosher', 'kp', 'kpmg', 'kpn', 'kr', 'krd',
                         'kred', 'kuokgroup', 'kw', 'ky', 'kyoto', 'kz', 'la', 'lacaixa', 'lamborghini', 'lamer',
                         'lancaster', 'land', 'landrover', 'lanxess', 'lasalle', 'lat', 'latrobe', 'law', 'lawyer',
                         'lb', 'lc', 'lds', 'lease', 'leclerc', 'legal', 'lego', 'lexus', 'lgbt', 'li', 'liaison',
                         'lidl', 'life', 'lifeinsurance', 'lifestyle', 'lighting', 'like', 'limited', 'limo',
                         'lincoln', 'linde', 'link', 'lipsy', 'live', 'living', 'lixil', 'lk', 'loan', 'loans',
                         'locker', 'locus', 'lol', 'london', 'lotte', 'lotto', 'love', 'lr', 'ls', 'lt', 'ltd', 'ltda',
                         'lu', 'lupin', 'luxe', 'luxury', 'lv', 'ly', 'ma', 'madrid', 'maif', 'maison', 'makeup', 'man',
                         'mango', 'market', 'marketing', 'markets', 'marriott', 'mattel', 'mba', 'mc',
                         'md', 'me', 'med', 'meet', 'melbourne', 'meme', 'memorial', 'men', 'meo',
                         'metlife', 'mg', 'mh', 'miami', 'microsoft', 'mil', 'mini', 'mk', 'ml', 'mlb', 'mls',
                         'mma', 'mn', 'mo', 'mobi', 'mobily', 'moda', 'moe', 'moi', 'mom', 'monash', 'money',
                         'montblanc', 'mormon', 'mortgage', 'moscow', 'mov', 'movie', 'movistar', 'mp',
                         'mq', 'mr', 'ms', 'mt', 'mtn', 'mtpc', 'mtr', 'mu', 'museum', 'mutual', 'mutuelle', 'mv', 'mw',
                         'mx', 'my', 'mz', 'na', 'nadex', 'nagoya', 'natura', 'navy', 'nc', 'ne', 'nec', 'net',
                         'netbank', 'netflix', 'network', 'neustar', 'new', 'news', 'next', 'nextdirect', 'nexus', 'nf',
                         'nfl', 'ng', 'ngo', 'nhk', 'ni', 'nico', 'nikon', 'ninja', 'nissan', 'nissay', 'nl', 'no',
                         'nokia', 'northwesternmutual', 'norton', 'now', 'nowruz', 'nowtv', 'np', 'nr', 'nra', 'nrw',
                         'ntt', 'nu', 'nyc', 'nz', 'obi', 'office', 'okinawa', 'olayan', 'olayangroup', 'ollo', 'om',
                         'omega', 'one', 'ong', 'onl', 'online', 'oracle', 'orange', 'org', 'organic',
                         'orientexpress', 'origins', 'osaka', 'otsuka', 'ott', 'ovh', 'pa', 'page', 'pamperedchef',
                         'panerai', 'paris', 'pars', 'partners', 'parts', 'party', 'passagens', 'pccw', 'pe', 'pet',
                         'pf', 'pg', 'ph', 'pharmacy', 'philips', 'photo', 'photography', 'photos', 'physio', 'piaget',
                         'pics', 'pictet', 'pictures', 'pid', 'pin', 'ping', 'pink', 'pioneer', 'pizza', 'pk', 'pl',
                         'place', 'play', 'playstation', 'plumbing', 'plus', 'pm', 'pn', 'pnc', 'pohl', 'poker',
                         'politie', 'porn', 'post', 'pr', 'praxi', 'press', 'prime', 'pro', 'prod', 'productions',
                         'prof', 'progressive', 'promo', 'protection', 'ps', 'pt', 'pub',
                         'pw', 'pwc', 'py', 'qa', 'qpon', 'quebec', 'quest', 'racing', 're', 'read', 'realestate',
                         'realtor', 'realty', 'recipes', 'red', 'redstone', 'redumbrella', 'rehab', 'reise', 'reisen',
                         'reit', 'ren', 'rent', 'rentals', 'repair', 'report', 'republican', 'rest', 'restaurant',
                         'review', 'reviews', 'rexroth', 'rich', 'richardli', 'ricoh', 'rio', 'rip', 'ro', 'rocher',
                         'rocks', 'rodeo', 'room', 'rs', 'rsvp', 'ru', 'ruhr', 'rw', 'rwe', 'ryukyu', 'sa',
                         'saarland', 'safe', 'safety', 'sakura', 'sale', 'salon', 'samsung', 'sandvik',
                         'sandvikcoromant', 'sanofi', 'sap', 'sapo', 'sarl', 'sas', 'save', 'saxo', 'sb', 'sbi', 'sbs',
                         'sc', 'sca', 'scb', 'schaeffler', 'schmidt', 'scholarships', 'school', 'schule', 'schwarz',
                         'science', 'scor', 'scot', 'sd', 'se', 'seat', 'seek', 'select', 'sener',
                         'seven', 'sew', 'sex', 'sexy', 'sfr', 'sg', 'sh', 'shangrila', 'sharp', 'shaw',
                         'shia', 'shiksha', 'shoes', 'shop', 'shopping', 'shouji', 'show', 'shriram', 'si',
                         'silk', 'sina', 'singles', 'site', 'sj', 'sk', 'ski', 'skin', 'sky', 'skype', 'sl', 'sm',
                         'smile', 'sn', 'sncf', 'so', 'soccer', 'social', 'softbank', 'software', 'sohu', 'solar',
                         'solutions', 'song', 'sony', 'soy', 'space', 'spiegel', 'spot', 'spreadbetting', 'sr', 'srl',
                         'st', 'stada', 'star', 'starhub', 'statebank', 'statefarm', 'statoil', 'stc', 'stcgroup',
                         'stockholm', 'storage', 'store', 'studio', 'study', 'su', 'sucks',
                         'supplies', 'supply', 'support', 'surf', 'surgery', 'suzuki', 'sv', 'swatch', 'swiss', 'sx',
                         'sy', 'sydney', 'symantec', 'systems', 'sz', 'tab', 'taipei', 'talk', 'taobao', 'tatamotors',
                         'tatar', 'tattoo', 'tax', 'taxi', 'tc', 'tci', 'td', 'tdk', 'team', 'tech', 'technology',
                         'tel', 'telecity', 'telefonica', 'temasek', 'tennis', 'teva', 'tf', 'tg', 'th', 'thd',
                         'theater', 'theatre', 'tickets', 'tienda', 'tiffany', 'tips', 'tires', 'tirol', 'tj', 'tk',
                         'tl', 'tm', 'tmall', 'tn', 'to', 'today', 'tokyo', 'toray', 'toshiba',
                         'total', 'tours', 'town', 'toyota', 'toys', 'tr', 'trade', 'trading', 'training', 'travel',
                         'travelchannel', 'travelers', 'travelersinsurance', 'trust', 'trv', 'tt', 'tube', 'tui',
                         'tunes', 'tushu', 'tv', 'tvs', 'tw', 'tz', 'ua', 'ubs', 'ug', 'uk', 'unicom', 'university',
                         'uno', 'uol', 'ups', 'us', 'uy', 'uz', 'va', 'vacations', 'vana', 'vc', 've', 'vegas',
                         'ventures', 'verisign', 'versicherung', 'vet', 'vg', 'vi', 'viajes', 'video', 'vig', 'viking',
                         'villas', 'vin', 'vip', 'virgin', 'vision', 'vista', 'vistaprint', 'viva', 'vlaanderen', 'vn',
                         'vodka', 'volkswagen', 'vote', 'voting', 'voto', 'voyage', 'vu', 'vuelos', 'wales', 'walter',
                         'wang', 'wanggou', 'warman', 'watch', 'watches', 'weather', 'weatherchannel', 'webcam',
                         'weber', 'website', 'wed', 'wedding', 'weibo', 'weir', 'wf', 'whoswho', 'wien', 'wiki',
                         'williamhill', 'win', 'windows', 'wine', 'wme', 'wolterskluwer', 'woodside', 'work', 'works',
                         'world', 'ws', 'wtc', 'wtf', 'xbox', 'xerox', 'xihuan', 'xin', 'xn--11b4c3d', 'xn--1ck2e1b',
                         'xn--1qqw23a', 'xn--30rr7y', 'xn--3bst00m', 'xn--3ds443g', 'xn--3e0b707e', 'xn--3pxu8k',
                         'xn--42c2d9a', 'xn--45brj9c', 'xn--45q11c', 'xn--4gbrim', 'xn--55qw42g', 'xn--55qx5d',
                         'xn--5su34j936bgsg', 'xn--5tzm5g', 'xn--6frz82g', 'xn--6qq986b3xl', 'xn--80adxhks',
                         'xn--80ao21a', 'xn--80asehdb', 'xn--80aswg', 'xn--8y0a063a', 'xn--90a3ac', 'xn--90ae',
                         'xn--90ais', 'xn--9dbq2a', 'xn--9et52u', 'xn--9krt00a', 'xn--b4w605ferd', 'xn--bck1b9a5dre4c',
                         'xn--c1avg', 'xn--c2br7g', 'xn--cck2b3b', 'xn--cg4bki', 'xn--clchc0ea0b2g2a9gcd',
                         'xn--czr694b', 'xn--czrs0t', 'xn--czru2d', 'xn--d1acj3b', 'xn--d1alf', 'xn--e1a4c',
                         'xn--eckvdtc9d', 'xn--efvy88h', 'xn--estv75g', 'xn--fct429k', 'xn--fhbei', 'xn--fiq228c5hs',
                         'xn--fiq64b', 'xn--fiqs8s', 'xn--fiqz9s', 'xn--fjq720a', 'xn--flw351e', 'xn--fpcrj9c3d',
                         'xn--fzc2c9e2c', 'xn--fzys8d69uvgm', 'xn--g2xx48c', 'xn--gckr3f0f', 'xn--gecrj9c',
                         'xn--h2brj9c', 'xn--hxt814e', 'xn--i1b6b1a6a2e', 'xn--imr513n', 'xn--io0a7i', 'xn--j1aef',
                         'xn--j1amh', 'xn--j6w193g', 'xn--jlq61u9w7b', 'xn--jvr189m', 'xn--kcrx77d1x4a', 'xn--kprw13d',
                         'xn--kpry57d', 'xn--kpu716f', 'xn--kput3i', 'xn--l1acc', 'xn--lgbbat1ad8j', 'xn--mgb9awbf',
                         'xn--mgba3a3ejt', 'xn--mgba3a4f16a', 'xn--mgba7c0bbn0a', 'xn--mgbaam7a8h', 'xn--mgbab2bd',
                         'xn--mgbayh7gpa', 'xn--mgbb9fbpob', 'xn--mgbbh1a71e', 'xn--mgbc0a9azcg', 'xn--mgbca7dzdo',
                         'xn--mgberp4a5d4ar', 'xn--mgbpl2fh', 'xn--mgbt3dhd', 'xn--mgbtx2b', 'xn--mgbx4cd0ab',
                         'xn--mix891f', 'xn--mk1bu44c', 'xn--mxtq1m', 'xn--ngbc5azd', 'xn--ngbe9e0a', 'xn--node',
                         'xn--nqv7f', 'xn--nqv7fs00ema', 'xn--nyqy26a', 'xn--o3cw4h', 'xn--ogbpf8fl', 'xn--p1acf',
                         'xn--p1ai', 'xn--pbt977c', 'xn--pgbs0dh', 'xn--pssy2u', 'xn--q9jyb4c', 'xn--qcka1pmc',
                         'xn--qxam', 'xn--rhqv96g', 'xn--rovu88b', 'xn--s9brj9c', 'xn--ses554g', 'xn--t60b56a',
                         'xn--tckwe', 'xn--unup4y', 'xn--vermgensberater-ctb', 'xn--vermgensberatung-pwb', 'xn--vhquv',
                         'xn--vuq861b', 'xn--w4r85el8fhu5dnra', 'xn--w4rs40l', 'xn--wgbh1c', 'xn--wgbl6a',
                         'xn--xhq521b', 'xn--xkc2al3hye2a', 'xn--xkc2dl3a5ee0h', 'xn--y9a3aq', 'xn--yfro4i67o',
                         'xn--ygbi2ammx', 'xn--zfr164b', 'xperia', 'xyz', 'yachts', 'yahoo', 'yamaxun',
                         'yandex', 'ye', 'yodobashi', 'yoga', 'yokohama', 'you', 'youtube', 'yt', 'yun', 'za', 'zappos',
                         'zara', 'zero', 'zippo', 'zm', 'zone', 'zuerich', 'zw'))

# --- PEStudio Patterns ------------------------------------------------------------------------------------------------

        with open('/opt/al/pkg/al_services/alsvc_frankenstrings/pestudio/xml/strings.xml', 'rt') as f:
            tree = ElementTree.parse(f)

        # Adding a min length for less FPs

        pest_minlen = 6

        self.pest_blacklist = {}
        self.pest_api = {}
        for ag in tree.findall('.//agent'):
            if len(ag.text) > pest_minlen:
                self.pest_blacklist.setdefault('agent', set()).add(ag.text)
        for av in tree.findall('.//av'):
            if len(av.text) > pest_minlen:
                self.pest_blacklist.setdefault('av', set()).add(av.text)
        for ev in tree.findall('.//event'):
            if len(ev.text) > pest_minlen:
                self.pest_blacklist.setdefault('event', set()).add(ev.text)
        for gu in tree.findall('.//guid'):
            if len(gu.text) > pest_minlen:
                self.pest_blacklist.setdefault('guid', set()).add(gu.text)
        for ins in tree.findall('.//insult'):
            if len(ins.text) > pest_minlen:
                self.pest_blacklist.setdefault('insult', set()).add(ins.text)
        for ke in tree.findall('.//key'):
            if len(ke.text) > pest_minlen:
                self.pest_blacklist.setdefault('key', set()).add(ke.text)
        for oi in tree.findall('.//oid'):
            if len(oi.text) > pest_minlen:
                self.pest_blacklist.setdefault('oid', set()).add(oi.text)
        for os in tree.findall('.//os'):
            if len(os.text) > pest_minlen:
                self.pest_blacklist.setdefault('os', set()).add(os.text)
        for pr in tree.findall('.//priv'):
            if len(pr.text) > pest_minlen:
                self.pest_blacklist.setdefault('priv', set()).add(pr.text)
        for pro in tree.findall('.//product'):
            if len(pro.text) > pest_minlen:
                self.pest_blacklist.setdefault('product', set()).add(pro.text)
        for reg in tree.findall('.//reg'):
            if len(reg.text) > pest_minlen:
                self.pest_blacklist.setdefault('reg', set()).add(reg.text)
        for si in tree.findall('.//sid'):
            if len(si.text) > pest_minlen:
                self.pest_blacklist.setdefault('sid', set()).add(si.text)
        for ssd in tree.findall('.//ssdl'):
            if len(ssd.text) > pest_minlen:
                self.pest_blacklist.setdefault('ssdl', set()).add(ssd.text)
        for st in tree.findall('.//string'):
            if len(st.text) > pest_minlen:
                self.pest_blacklist.setdefault('string', set()).add(st.text)

        # Adding Popular API
        with open('/opt/al/pkg/al_services/alsvc_frankenstrings/pestudio/xml/functions.xml', 'rt') as f:
            tree = ElementTree.parse(f)

        for fun in tree.findall(".//fct"):
            if fun.text is not None:
                if len(fun.text) > pest_minlen and fun.text is not None:
                    self.pest_api.setdefault('fct', set()).add(fun.text.split('::', 1)[0])
        for li in tree.findall(".//lib"):
            if hasattr(li, 'name') and li.name is not None:
                if len(li.name) > pest_minlen:
                    self.pest_api.setdefault('lib', set()).add(li.get("name"))
        for tapi in tree.findall('.//topapi'):
            if tapi.text is not None:
                if len(tapi.text) > pest_minlen:
                    self.pest_api.setdefault('topapi', set()).add(tapi.text)

# --- Regex Patterns ---------------------------------------------------------------------------------------------------

        self.pat_domain = r'(?i)\b(?:[A-Z0-9-]+\.)+(?:[A-Z]{2,12}|XN--[A-Z0-9]{4,18})\b'
        self.pat_filecom = r'(?i)\b[- _A-Z0-9.\\]{0,75}[%]?' \
                           r'(?:ALLUSERPROFILE|APPDATA|commonappdata|CommonProgramFiles|HOMEPATH|LOCALAPPDATA|' \
                           r'ProgramData|ProgramFiles|PUBLIC|SystemDrive|SystemRoot|\\TEMP|USERPROFILE|' \
                           r'windir|system32|syswow64|\\user)' \
                           r'[%]?\\[-_A-Z0-9\.\\]{1,200}\b'
        self.pat_fileext = r'(?i)\b[a-z]?[:]?[-_A-Z0-9.\\]{0,200}\w\.' \
                           r'(?:7Z|BAT|BIN|CLASS|CMD|DAT|DOC|DOCX|DLL|EML|EXE|JAR|JPG|JS|JSE|LOG|MSI|PDF|PNG|PPT|PPTX' \
                           r'|RAR|RTF|SCR|SWF|SYS|[T]?BZ[2]?|TXT|TMP|VBE|VBS|XLS|XLSX|ZIP)\b'
        self.pat_filepdb = r'(?i)\b[-_A-Z0-9.\\]{0,200}\w\.PDB\b'
        self.pat_email = r'(?i)\b[A-Z0-9._%+-]{3,}@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2,12}|XN--[A-Z0-9]{4,18})\b'
        self.pat_ip = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        self.pat_regis = r'(?i)\b[- _A-Z0-9.\\]{0,25}' \
                         r'(?:controlset001|controlset002|currentcontrolset|currentversion|HKCC|HKCR|HKCU|HKDD|' \
                         r'hkey_classes_root|hkey_current_config|hkey_current_user|hkey_dyn_data|hkey_local_machine|' \
                         r'HKLM|hkey_performance_data|hkey_users|HKPD|internet settings|\\sam|\\software|\\system|' \
                         r'\\userinit)' \
                         r'\\[-_A-Z0-9.\\ ]{1,200}\b'
        self.pat_url = r'(?i)(?:http|https|ftp)://[A-Z0-9/\-\.&%\$#=~\?]{3,200}'
        self.pat_exedos = r'This program cannot be run in DOS mode'
        self.pat_exeheader = r'(?s)MZ.{32,1024}PE\000\000'

# --- Find Match for IOC Regex, Return Dictionary: {[AL Tag Type:(Match Values)]} --------------------------------------

    def ioc_match(self, value, bogon_ip=None):
        from fuzzywuzzy import process
        # NOTES:
        # '(?i)' makes a regex case-insensitive
        # \b matches a word boundary, it can help speeding up regex search and avoiding some false positives.
        # See http://www.regular-expressions.info/wordboundaries.html
        value_extract = {}
        # ------------------------------------------------------------------------------
        # IP ADDRESSES
        # Pattern_re("IP addresses", r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", weight=10),
        # Here I use \b to make sure there is no other digit around and to speedup search
        #print("ips")
        final_values = ""
        find_ip = re.findall(self.pat_ip, value)
        if len(find_ip) > 0:
            longeststring = max(find_ip, key=len)
            like_ls = process.extract(longeststring, find_ip, limit=50)
            final_values = filter(lambda ls: ls[1] < 99, like_ls)
            final_values.append((longeststring, 100))
            for val in final_values:
                not_filtered = self.ipv4_filter(val[0], bogon=bogon_ip)
                if not_filtered:
                    value_extract.setdefault('NET_IP', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # URLs
        #print("urls")
        final_values = ""
        find_url = re.findall(self.pat_url, value)
        if len(find_url) > 0:
            longeststring = max(find_url, key=len)
            like_ls = process.extract(longeststring, find_url, limit=50)
            final_values = filter(lambda ls: ls[1] < 95, like_ls)
            final_values.append((longeststring, 100))
            for val in final_values:
                value_extract.setdefault('NET_FULL_URI', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # E-MAIL ADDRESSES
        # r'(?i)\b[A-Z0-9._%+-]+@(?:[A-Z0-9-]+\.)+(?:[A-Z]{2}|com|org|net|edu|gov|mil|int|biz|info|mobi|name|aero|asia|jobs|museum)\b',
        # changed to catch all current TLDs registered at IANA (in combination with filter function):
        # TLD = either only chars from 2 to 12, or 'XN--' followed by up to 18 chars and digits
        #print("emails")
        final_values = ""
        find_email = re.findall(self.pat_email, value)
        if len(find_email) > 0:
            longeststring = max(find_email, key=len)
            like_ls = process.extract(longeststring, find_email, limit=50)
            final_values = filter(lambda ls: ls[1] < 95, like_ls)
            final_values.append((longeststring, 100))
            for val in final_values:
                not_filtered = self.email_filter(val[0])
                if not_filtered:
                    value_extract.setdefault('NET_EMAIL', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # DOMAIN NAMES
        # Old: r'(?=^.{1,254}$)(^(?:(?!\d+\.|-)[a-zA-Z0-9_\-]{1,63}(?<!-)\.?)+(?:[a-zA-Z]{2,})$)'
        # Below is taken from email regex above
        #print("domains")
        final_values = ""
        find_domain = re.findall(self.pat_domain, value)
        if len(find_domain) > 0 and len(max(find_domain, key=len)) > 11:
            longeststring = max(find_domain, key=len)
            like_ls = process.extract(longeststring, find_domain, limit=50)
            final_values = filter(lambda ls: ls[1] < 95, like_ls)
            final_values.append((longeststring, 100))
            for val in final_values:
                not_filtered = self.domain_filter(val[0])
                if not_filtered:
                    value_extract.setdefault('NET_DOMAIN_NAME', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # FILENAMES
        # Check length
        # Ends with extension of interest or contains strings of interest
        #print("files")
        final_values = ""
        if len(value) > 6:
            filefind_pdb = re.findall(self.pat_filepdb, value)
            if len(filefind_pdb) > 0:
                if len(max(filefind_pdb, key=len)) > 6:
                    longeststring = max(filefind_pdb, key=len)
                    like_ls = process.extract(longeststring, filefind_pdb, limit=50)
                    final_values = filter(lambda ls: ls[1] < 95, like_ls)
                    final_values.append((longeststring, 100))
                    for val in final_values:
                        value_extract.setdefault('FILE_PDB_STRING', set()).add(val[0])
            filefind_ext = re.findall(self.pat_fileext, value)
            if len(filefind_ext) > 0:
                if len(max(filefind_ext, key=len)) > 6:
                    longeststring = max(filefind_ext, key=len)
                    like_ls = process.extract(longeststring, filefind_ext, limit=50)
                    final_values = filter(lambda ls: ls[1] < 95, like_ls)
                    final_values.append((longeststring, 100))
                    for val in final_values:
                        value_extract.setdefault('FILE_NAME', set()).add(val[0])
            filefind_com = re.findall(self.pat_filecom, value)
            if len(filefind_com) > 0 and len(max(filefind_com, key=len)) > 6:
                longeststring = max(filefind_com, key=len)
                like_ls = process.extract(longeststring, filefind_com, limit=50)
                final_values = filter(lambda ls: ls[1] < 95, like_ls)
                final_values.append((longeststring, 100))
                for val in final_values:
                    value_extract.setdefault('FILE_NAME', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # REGISTRYKEYS
        # Looks for alpha numeric characters seperated by at least two sets of '\'s
        #print("reg")
        final_values = ""
        regfind = re.findall(self.pat_regis, value)
        if len(regfind) > 0 and len(max(regfind, key=len)) > 15:
            longeststring = max(regfind, key=len)
            like_ls = process.extract(longeststring, regfind, limit=50)
            final_values = filter(lambda ls: ls[1] < 90, like_ls)
            final_values.append((longeststring, 100))
            for val in final_values:
                value_extract.setdefault('REGISTRY_KEY', set()).add(val[0])
        # ------------------------------------------------------------------------------
        # PEStudio Blacklist
        # Flags strings from PEStudio's Blacklist
        final_values = ""
        for k, i in self.pest_blacklist.iteritems():
            for e in i:
                psblfind = []
                if e in value:
                    psblfind.append(e)
                if len(psblfind) > 0:
                    longeststring = max(psblfind, key=len)
                    like_ls = process.extract(longeststring, psblfind, limit=50)
                    final_values = filter(lambda ls: ls[1] < 95, like_ls)
                    final_values.append((longeststring, 100))
                    for val in final_values:
                        value_extract.setdefault('PESTUDIO_BLACKLIST_STRING', set()).add(val[0])
        # -----------------------------------------------------------------------------
        # Function/Library Strings
        # Win API strings from PEStudio's Blacklist
        final_values = ""
        for k, i in self.pest_api.iteritems():
            for e in i:
                pswinfind = []
                if e in value:
                    pswinfind.append(e)
                if len(pswinfind) > 0:
                    longeststring = max(pswinfind, key=len)
                    like_ls = process.extract(longeststring, pswinfind, limit=50)
                    final_values = filter(lambda ls: ls[1] < 95, like_ls)
                    final_values.append((longeststring, 100))
                    for val in final_values:
                        value_extract.setdefault('WIN_API_STRING', set()).add(val[0])

        return value_extract

# --- Filters ----------------------------------------------------------------------------------------------------------

    @staticmethod
    def ipv4_filter(value, index=0, pattern=None, bogon=None):
        """
        IPv4 address filter:
        - check if string length is >7 (e.g. not just 4 digits and 3 dots)
        - check if not in list of bogon IP addresses
        return True if OK, False otherwise.
        """
        ip = value
        # check if string length is >7 (e.g. not just 4 digits and 3 dots)
        if len(ip) < 8:
            return False

        # 0.0.0.0 255.0.0.0e
        if ip.startswith('0'): return False
        if int(ip.split(".", 1)[0]) > 255: return False

        # also reject IPs ending with .0 or .255
        if ip.endswith('.0') or ip.endswith('.255'): return False

        # BOGON IP ADDRESS RANGES:
        # source: http://www.team-cymru.org/Services/Bogons/bogon-dd.html

        if bogon is not None:
            # extract 1st and 2nd decimal number from IP as int:
            ip_bytes = ip.split('.')
            byte1 = int(ip_bytes[0])
            byte2 = int(ip_bytes[1])
            # print 'ip=%s byte1=%d byte2=%d' % (ip, byte1, byte2)

            # actually we might want to see the following bogon IPs if malware uses them
            # => this should be an option
            # 10.0.0.0 255.0.0.0
            if ip.startswith('10.'): return False
            # 100.64.0.0 255.192.0.0
            if ip.startswith('100.') and (byte2&192 == 64): return False
            # 127.0.0.0 255.0.0.0
            if ip.startswith('127.'): return False
            # 169.254.0.0 255.255.0.0
            if ip.startswith('169.254.'): return False
            # 172.16.0.0 255.240.0.0
            if ip.startswith('172.') and (byte2&240 == 16): return False
            # 192.0.0.0 255.255.255.0
            if ip.startswith('192.0.0.'): return False
            # 192.0.2.0 255.255.255.0
            if ip.startswith('192.0.2.'): return False
            # 192.168.0.0 255.255.0.0
            if ip.startswith('192.168.'): return False
            # 198.18.0.0 255.254.0.0
            if ip.startswith('198.') and (byte2&254 == 18): return False
            # 198.51.100.0 255.255.255.0
            if ip.startswith('198.51.100.'): return False
            # 203.0.113.0 255.255.255.0
            if ip.startswith('203.0.113.'): return False
            # 224.0.0.0 240.0.0.0
            if byte1&240 == 224: return False
            # 240.0.0.0 240.0.0.0
            if byte1&240 == 240: return False

        # otherwise it's a valid IP adress
        return True

    def email_filter(self, value, index=0, pattern=None):
        # check length, e.g. longer than xy@hp.fr
        # check case? e.g. either lower, upper, or capital (but CamelCase covers
        # almost everything... the only rejected case would be starting with lower
        # and containing upper?)
        # or reject mixed case in last part of domain name? (might filter 50% of
        # false positives)
        # optionally, DNS MX query with caching?

        user, domain = value.split('@', 1)
        if len(user) < 2:
            return False
        if len(domain) < 5:
            return False
        tld = domain.rsplit('.', 1)[1].lower()
        if tld not in self.tlds:
            return False

        return True

    def domain_filter(self, value, index=0, pattern=None):
        # check length
        # check match again tlds set
        if len(value) < 13:
            return False
        uniq_char = ''.join(set(value))
        if len(uniq_char) < 6:
            return False
        fld = value.split('.')
        tld = value.rsplit('.', 1)[1].lower()
        # If only two domain levels and either bottom level <= 2 char or tld <= 2 char, or top-level not in list
        if (len(fld) <= 2 and len(fld[0]) <= 2) or (len(fld) <= 2 and len(tld) <= 2) or tld not in self.tlds:
            return False
        return True

    @staticmethod
    def str_filter(value, index=0, pattern=None):
        """
        String filter: avoid false positives with random case. A typical string
        should be either:
        - all UPPERCASE
        - all lowercase
        - or Capitalized
        return True if OK, False otherwise.
        Usage: This filter is meant to be used with string patterns that catch words
        with the option nocase=True, but where random case is not likely.
        Note 1: It is assumed the string only contains alphabetical characters (a-z)
        Note 2: this filter does not cover CamelCase strings.
        """
        # case 1: all UPPERCASE
        # case 2: all lowercase except 1st character which can be uppercase (Capitalized)
        if value.isupper() or value[1:].islower(): return True
        #Note: we could also use istitle() if strings are not only alphabetical.

    @staticmethod
    def len_filter(value, index=0, pattern=None, bogon=None):
        if len(value) < 10:
            return False
        return True

# --- BBCrack Patterns -------------------------------------------------------------------------------------------------

    def bbcr(self):

        bbcrack_patterns = [
            Pattern("EXE_DOS", self.pat_exedos, nocase=True, weight=10000),
            Pattern_re("EXE_HEAD", self.pat_exeheader, weight=100),
        ]

        # Add PEStudio's API String list, weight will default to 1
        for k, i in self.pest_api.iteritems():
            if k == "topapi" or k == "lib":
                for e in i:
                    if len(e) > 7:
                        bbcrack_patterns.append(Pattern('WIN_API_STRING', e, nocase=True, weight=1000))

        return bbcrack_patterns
