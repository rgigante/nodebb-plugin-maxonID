'use strict';

(function (module) {
	const commonWords = ['people', 'history', 'way', 'art', 'world', 'information', 'map', 'two', 'family', 'government', 'health', 'system', 'computer', 'meat', 'year', 'thanks', 'music', 'person', 'reading', 'method', 'data', 'food', 'understanding', 'theory', 'law', 'bird', 'literature', 'problem', 'software', 'control', 'knowledge', 'power', 'ability', 'economics', 'love', 'internet', 'television', 'science', 'library', 'nature', 'fact', 'product', 'idea', 'temperature', 'investment', 'area', 'society', 'activity', 'story', 'industry', 'media', 'thing', 'oven', 'community', 'definition', 'safety', 'quality', 'development', 'language', 'management', 'player', 'variety', 'video', 'week', 'security', 'country', 'exam', 'movie', 'organization', 'equipment', 'physics', 'analysis', 'policy', 'series', 'thought', 'basis', 'boyfriend', 'direction', 'strategy', 'technology', 'army', 'camera', 'freedom', 'paper', 'environment', 'child', 'instance', 'month', 'truth', 'marketing', 'university', 'writing', 'article', 'department', 'difference', 'goal', 'news', 'audience', 'fishing', 'growth', 'income', 'marriage', 'user', 'combination', 'failure', 'meaning', 'medicine', 'philosophy', 'teacher', 'communication', 'night', 'chemistry', 'disease', 'disk', 'energy', 'nation', 'road', 'role', 'soup', 'advertising', 'location', 'success', 'addition', 'apartment', 'education', 'math', 'moment', 'painting', 'politics', 'attention', 'decision', 'event', 'property', 'shopping', 'student', 'wood', 'competition', 'distribution', 'entertainment', 'office', 'population', 'president', 'unit', 'category', 'cigarette', 'context', 'introduction', 'opportunity', 'performance', 'driver', 'flight', 'length', 'magazine', 'newspaper', 'relationship', 'teaching', 'cell', 'dealer', 'finding', 'lake', 'member', 'message', 'phone', 'scene', 'appearance', 'association', 'concept', 'customer', 'death', 'discussion', 'housing', 'inflation', 'insurance', 'mood', 'woman', 'advice', 'blood', 'effort', 'expression', 'importance', 'opinion', 'payment', 'reality', 'responsibility', 'situation', 'skill', 'statement', 'wealth', 'application', 'city', 'county', 'depth', 'estate', 'foundation', 'grandmother', 'heart', 'perspective', 'photo', 'recipe', 'studio', 'topic', 'collection', 'depression', 'imagination', 'passion', 'percentage', 'resource', 'setting', 'ad', 'agency', 'college', 'connection', 'criticism', 'debt', 'description', 'memory', 'patience', 'secretary', 'solution', 'administration', 'aspect', 'attitude', 'director', 'personality', 'psychology', 'recommendation', 'response', 'selection', 'storage', 'version', 'alcohol', 'argument', 'complaint', 'contract', 'emphasis', 'highway', 'loss', 'membership', 'possession', 'preparation', 'steak', 'union', 'agreement', 'cancer', 'currency', 'employment', 'engineering', 'entry', 'interaction', 'mixture', 'preference', 'region', 'republic', 'tradition', 'virus', 'actor', 'classroom', 'delivery', 'device', 'difficulty', 'drama', 'election', 'engine', 'football', 'guidance', 'hotel', 'owner', 'priority', 'protection', 'suggestion', 'tension', 'variation', 'anxiety', 'atmosphere', 'awareness', 'bath', 'bread', 'candidate', 'climate', 'comparison', 'confusion', 'construction', 'elevator', 'emotion', 'employee', 'employer', 'guest', 'height', 'leadership', 'mall', 'manager', 'operation', 'recording', 'sample', 'transportation', 'charity', 'cousin', 'disaster', 'editor', 'efficiency', 'excitement', 'extent', 'feedback', 'guitar', 'homework', 'leader', 'mom', 'outcome', 'permission', 'presentation', 'promotion', 'reflection', 'refrigerator', 'resolution', 'revenue', 'session', 'singer', 'tennis', 'basket', 'bonus', 'cabinet', 'childhood', 'church', 'clothes', 'coffee', 'dinner', 'drawing', 'hair', 'hearing', 'initiative', 'judgment', 'lab', 'measurement', 'mode', 'mud', 'orange', 'poetry', 'police', 'possibility', 'procedure', 'queen', 'ratio', 'relation', 'restaurant', 'satisfaction', 'sector', 'signature', 'significance', 'song', 'tooth', 'town', 'vehicle', 'volume', 'wife', 'accident', 'airport', 'appointment', 'arrival', 'assumption', 'baseball', 'chapter', 'committee', 'conversation', 'database', 'enthusiasm', 'error', 'explanation', 'farmer', 'gate', 'girl', 'hall', 'historian', 'hospital', 'injury', 'instruction', 'maintenance', 'manufacturer', 'meal', 'perception', 'pie', 'poem', 'presence', 'proposal', 'reception', 'replacement', 'revolution', 'river', 'son', 'speech', 'tea', 'village', 'warning', 'winner', 'worker', 'writer', 'assistance', 'breath', 'buyer', 'chest', 'chocolate', 'conclusion', 'contribution', 'cookie', 'courage', 'dad', 'desk', 'drawer', 'establishment', 'examination', 'garbage', 'grocery', 'honey', 'impression', 'improvement', 'independence', 'insect', 'inspection', 'inspector', 'king', 'ladder', 'menu', 'penalty', 'piano', 'potato', 'profession', 'professor', 'quantity', 'reaction', 'requirement', 'salad', 'sister', 'supermarket', 'tongue', 'weakness', 'wedding', 'affair', 'ambition', 'analyst', 'apple', 'assignment', 'assistant', 'bathroom', 'bedroom', 'beer', 'birthday', 'celebration', 'championship', 'cheek', 'client', 'consequence', 'departure', 'diamond', 'dirt', 'ear', 'fortune', 'friendship', 'funeral', 'gene', 'girlfriend', 'hat', 'indication', 'intention', 'lady', 'midnight', 'negotiation', 'obligation', 'passenger', 'pizza', 'platform', 'poet', 'pollution', 'recognition', 'reputation', 'shirt', 'sir', 'speaker', 'stranger', 'surgery', 'sympathy', 'tale', 'throat', 'trainer', 'uncle', 'youth', 'time', 'work', 'film', 'water', 'money', 'example', 'while', 'business', 'study', 'game', 'life', 'form', 'air', 'day', 'place', 'number', 'part', 'field', 'fish', 'back', 'process', 'heat', 'hand', 'experience', 'job', 'book', 'end', 'point', 'type', 'home', 'economy', 'value', 'body', 'market', 'guide', 'interest', 'state', 'radio', 'course', 'company', 'price', 'size', 'card', 'list', 'mind', 'trade', 'line', 'care', 'group', 'risk', 'word', 'fat', 'force', 'key', 'light', 'training', 'name', 'school', 'top', 'amount', 'level', 'order', 'practice', 'research', 'sense', 'service', 'piece', 'web', 'boss', 'sport', 'fun', 'house', 'page', 'term', 'test', 'answer', 'sound', 'focus', 'matter', 'kind', 'soil', 'board', 'oil', 'picture', 'access', 'garden', 'range', 'rate', 'reason', 'future', 'site', 'demand', 'exercise', 'image', 'case', 'cause', 'coast', 'action', 'age', 'bad', 'boat', 'record', 'result', 'section', 'building', 'mouse', 'cash', 'class', 'nothing', 'period', 'plan', 'store', 'tax', 'side', 'subject', 'space', 'rule', 'stock', 'weather', 'chance', 'figure', 'man', 'model', 'source', 'beginning', 'earth', 'program', 'chicken', 'design', 'feature', 'head', 'material', 'purpose', 'question', 'rock', 'salt', 'act', 'birth', 'car', 'dog', 'object', 'scale', 'sun', 'note', 'profit', 'rent', 'speed', 'style', 'war', 'bank', 'craft', 'half', 'inside', 'outside', 'standard', 'bus', 'exchange', 'eye', 'fire', 'position', 'pressure', 'stress', 'advantage', 'benefit', 'box', 'frame', 'issue', 'step', 'cycle', 'face', 'item', 'metal', 'paint', 'review', 'room', 'screen', 'structure', 'view', 'account', 'ball', 'discipline', 'medium', 'share', 'balance', 'bit', 'black', 'bottom', 'choice', 'gift', 'impact', 'machine', 'shape', 'tool', 'wind', 'address', 'average', 'career', 'culture', 'morning', 'pot', 'sign', 'table', 'task', 'condition', 'contact', 'credit', 'egg', 'hope', 'ice', 'network', 'north', 'square', 'attempt', 'date', 'effect', 'link', 'post', 'star', 'voice', 'capital', 'challenge', 'friend', 'self', 'shot', 'brush', 'couple', 'debate', 'exit', 'front', 'function', 'lack', 'living', 'plant', 'plastic', 'spot', 'summer', 'taste', 'theme', 'track', 'wing', 'brain', 'button', 'click', 'desire', 'foot', 'gas', 'influence', 'notice', 'rain', 'wall', 'base', 'damage', 'distance', 'feeling', 'pair', 'savings', 'staff', 'sugar', 'target', 'text', 'animal', 'author', 'budget', 'discount', 'file', 'ground', 'lesson', 'minute', 'officer', 'phase', 'reference', 'register', 'sky', 'stage', 'stick', 'title', 'trouble', 'bowl', 'bridge', 'campaign', 'character', 'club', 'edge', 'evidence', 'fan', 'letter', 'lock', 'maximum', 'novel', 'option', 'pack', 'park', 'plenty', 'quarter', 'skin', 'sort', 'weight', 'baby', 'background', 'carry', 'dish', 'factor', 'fruit', 'glass', 'joint', 'master', 'muscle', 'red', 'strength', 'traffic', 'trip', 'vegetable', 'appeal', 'chart', 'gear', 'ideal', 'kitchen', 'land', 'log', 'mother', 'net', 'party', 'principle', 'relative', 'sale', 'season', 'signal', 'spirit', 'street', 'tree', 'wave', 'belt', 'bench', 'commission', 'copy', 'drop', 'minimum', 'path', 'progress', 'project', 'sea', 'south', 'status', 'stuff', 'ticket', 'tour', 'angle', 'blue', 'breakfast', 'confidence', 'daughter', 'degree', 'doctor', 'dot', 'dream', 'duty', 'essay', 'father', 'fee', 'finance', 'hour', 'juice', 'limit', 'luck', 'milk', 'mouth', 'peace', 'pipe', 'seat', 'stable', 'storm', 'substance', 'team', 'trick', 'afternoon', 'bat', 'beach', 'blank', 'catch', 'chain', 'consideration', 'cream', 'crew', 'detail', 'gold', 'interview', 'kid', 'mark', 'match', 'mission', 'pain', 'pleasure', 'score', 'screw', 'sex', 'shop', 'shower', 'suit', 'tone', 'window', 'agent', 'band', 'block', 'bone', 'calendar', 'cap', 'coat', 'contest', 'corner', 'court', 'cup', 'district', 'door', 'east', 'finger', 'garage', 'guarantee', 'hole', 'hook', 'implement', 'layer', 'lecture', 'lie', 'manner', 'meeting', 'nose', 'parking', 'partner', 'profile', 'respect', 'rice', 'routine', 'schedule', 'swimming', 'telephone', 'tip', 'winter', 'airline', 'bag', 'battle', 'bed', 'bill', 'bother', 'cake', 'code', 'curve', 'designer', 'dimension', 'dress', 'ease', 'emergency', 'evening', 'extension', 'farm', 'fight', 'gap', 'grade', 'holiday', 'horror', 'horse', 'host', 'husband', 'loan', 'mistake', 'mountain', 'nail', 'noise', 'occasion', 'package', 'patient', 'pause', 'phrase', 'proof', 'race', 'relief', 'sand', 'sentence', 'shoulder', 'smoke', 'stomach', 'string', 'tourist', 'towel', 'vacation', 'west', 'wheel', 'wine', 'arm', 'aside', 'associate', 'bet', 'blow', 'border', 'branch', 'breast', 'brother', 'buddy', 'bunch', 'chip', 'coach', 'cross', 'document', 'draft', 'dust', 'expert', 'floor', 'god', 'golf', 'habit', 'iron', 'judge', 'knife', 'landscape', 'league', 'mail', 'mess', 'native', 'opening', 'parent', 'pattern', 'pin', 'pool', 'pound', 'request', 'salary', 'shame', 'shelter', 'shoe', 'silver', 'tackle', 'tank', 'trust', 'assist', 'bake', 'bar', 'bell', 'bike', 'blame', 'boy', 'brick', 'chair', 'closet', 'clue', 'collar', 'comment', 'conference', 'devil', 'diet', 'fear', 'fuel', 'glove', 'jacket', 'lunch', 'monitor', 'mortgage', 'nurse', 'pace', 'panic', 'peak', 'plane', 'reward', 'row', 'sandwich', 'shock', 'spite', 'spray', 'surprise', 'till', 'transition', 'weekend', 'welcome', 'yard', 'alarm', 'bend', 'bicycle', 'bite', 'blind', 'bottle', 'cable', 'candle', 'clerk', 'cloud', 'concert', 'counter', 'flower', 'grandfather', 'harm', 'knee', 'lawyer', 'leather', 'load', 'mirror', 'neck', 'pension', 'plate', 'purple', 'ruin', 'ship', 'skirt', 'slice', 'snow', 'specialist', 'stroke', 'switch', 'trash', 'tune', 'zone', 'anger', 'award', 'bid', 'bitter', 'boot', 'bug', 'camp', 'candy', 'carpet', 'cat', 'champion', 'channel', 'clock', 'comfort', 'cow', 'crack', 'engineer', 'entrance', 'fault', 'grass', 'guy', 'hell', 'highlight', 'incident', 'island', 'joke', 'jury', 'leg', 'lip', 'mate', 'motor', 'nerve', 'passage', 'pen', 'pride', 'priest', 'prize', 'promise', 'resident', 'resort', 'ring', 'roof', 'rope', 'sail', 'scheme', 'script', 'sock', 'station', 'toe', 'tower', 'truck', 'witness', 'a', 'you', 'it', 'can', 'will', 'if', 'one', 'many', 'most', 'other', 'use', 'make', 'good', 'look', 'help', 'go', 'great', 'being', 'few', 'might', 'still', 'public', 'read', 'keep', 'start', 'give', 'human', 'local', 'general', 'she', 'specific', 'long', 'play', 'feel', 'high', 'tonight', 'put', 'common', 'set', 'change', 'simple', 'past', 'big', 'possible', 'particular', 'today', 'major', 'personal', 'current', 'national', 'cut', 'natural', 'physical', 'show', 'try', 'check', 'second', 'call', 'move', 'pay', 'let', 'increase', 'single', 'individual', 'turn', 'ask', 'buy', 'guard', 'hold', 'main', 'offer', 'potential', 'professional', 'international', 'travel', 'cook', 'alternative', 'following', 'special', 'working', 'whole', 'dance', 'excuse', 'cold', 'commercial', 'low', 'purchase', 'deal', 'primary', 'worth', 'fall', 'necessary', 'positive', 'produce', 'search', 'present', 'spend', 'talk', 'creative', 'tell', 'cost', 'drive', 'green', 'support', 'glad', 'remove', 'return', 'run', 'complex', 'due', 'effective', 'middle', 'regular', 'reserve', 'independent', 'leave', 'original', 'reach', 'rest', 'serve', 'watch', 'beautiful', 'charge', 'active', 'break', 'negative', 'safe', 'stay', 'visit', 'visual', 'affect', 'cover', 'report', 'rise', 'walk', 'white', 'beyond', 'junior', 'pick', 'unique', 'anything', 'classic', 'final', 'lift', 'mix', 'private', 'stop', 'teach', 'western', 'concern', 'familiar', 'fly', 'official', 'broad', 'comfortable', 'gain', 'maybe', 'rich', 'save', 'stand', 'young', 'fail', 'heavy', 'hello', 'lead', 'listen', 'valuable', 'worry', 'handle', 'leading', 'meet', 'release', 'sell', 'finish', 'normal', 'press', 'ride', 'secret', 'spread', 'spring', 'tough', 'wait', 'brown', 'deep', 'display', 'flow', 'hit', 'objective', 'shoot', 'touch', 'cancel', 'chemical', 'cry', 'dump', 'extreme', 'push', 'conflict', 'eat', 'fill', 'formal', 'jump', 'kick', 'opposite', 'pass', 'pitch', 'remote', 'total', 'treat', 'vast', 'abuse', 'beat', 'burn', 'deposit', 'print', 'raise', 'sleep', 'somewhere', 'advance', 'anywhere', 'consist', 'dark', 'double', 'draw', 'equal', 'fix', 'hire', 'internal', 'join', 'kill', 'sensitive', 'tap', 'win', 'attack', 'claim', 'constant', 'drag', 'drink', 'guess', 'minor', 'pull', 'raw', 'soft', 'solid', 'wear', 'weird', 'wonder', 'annual', 'count', 'dead', 'doubt', 'feed', 'forever', 'impress', 'nobody', 'repeat', 'round', 'sing', 'slide', 'strip', 'whereas', 'wish', 'combine', 'command', 'dig', 'divide', 'equivalent', 'hang', 'hunt', 'initial', 'march', 'mention', 'smell', 'spiritual', 'survey', 'tie', 'adult', 'brief', 'crazy', 'escape', 'gather', 'hate', 'prior', 'repair', 'rough', 'sad', 'scratch', 'sick', 'strike', 'employ', 'external', 'hurt', 'illegal', 'laugh', 'lay', 'mobile', 'nasty', 'ordinary', 'respond', 'royal', 'senior', 'split', 'strain', 'struggle', 'swim', 'train', 'upper', 'wash', 'yellow', 'convert', 'crash', 'dependent', 'fold', 'funny', 'grab', 'hide', 'miss', 'permit', 'quote', 'recover', 'resolve', 'roll', 'sink', 'slip', 'spare', 'suspect', 'sweet', 'swing', 'twist', 'upstairs', 'usual', 'abroad', 'brave', 'calm', 'concentrate', 'estimate', 'grand', 'male', 'mine', 'prompt', 'quiet', 'refuse', 'regret', 'reveal', 'rush', 'shake', 'shift', 'shine', 'steal', 'suck', 'surround', 'anybody', 'bear', 'brilliant', 'dare', 'dear', 'delay', 'drunk', 'female', 'hurry', 'inevitable', 'invite', 'kiss', 'neat', 'pop', 'punch', 'quit', 'reply', 'representative', 'resist', 'rip', 'rub', 'silly', 'smile', 'spell', 'stretch', 'stupid', 'tear', 'temporary', 'tomorrow', 'wake', 'wrap', 'yesterday'];

	const user = require.main.require('./src/user');
	const groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');

	const async = require('async');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	// use Unirest API or Request API for making https requests
	const useUnirestAPI = true;

	// create constants object
	const constants = Object.freeze({
		name: nconf.get('oauth_plugin:name'),
		oauth2: {
			authorizationURL: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:authorizationURL'),
			tokenURL: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:tokenURL'),
			logoutURL: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:logoutURL'),
			clientID: nconf.get('oauth_plugin:clientID'),
			clientSecret: nconf.get('oauth_plugin:clientSecret'),
		},
		userRoute: nconf.get('oauth_plugin:idserver') + nconf.get('oauth_plugin:userRoute'),
		scope: nconf.get('oauth_plugin:scope'),
		allowedEntitlementsList: nconf.get('oauth_plugin:allowedEntitlements').split(','),
		premiumGroupId: nconf.get('oauth_plugin:premiumGroupId'),
		setFullname: nconf.get('oauth_plugin:setFullname'),
		debugOutput: nconf.get('oauth_plugin:enableDebugOutput'),
		usernameStrategy: nconf.get('oauth_plugin:usernameStrategy'), // two-words, email, name_surname, nickname
	});

	if (constants.debugOutput !== undefined && constants.debugOutput) {
		winston.verbose('[maxonID] Configuration');
		console.log(constants);
	}

	// check the contants object for contain data
	let configOk = false;
	if (constants.name === undefined || constants.name === '') {
		winston.error('[maxonID] Please specify a name for your OAuth provider');
	} else if (constants.oauth2.clientID === undefined || constants.oauth2.clientID === '') {
		winston.error('[maxonID] ClientID required');
	} else if (constants.oauth2.clientSecret === undefined || constants.oauth2.clientSecret === '') {
		winston.error('[maxonID] Client Secret required');
	} else if (constants.oauth2.authorizationURL === undefined || constants.oauth2.authorizationURL === '') {
		winston.error('[maxonID] Authorization URL required');
	} else if (constants.oauth2.tokenURL === undefined || constants.oauth2.tokenURL === '') {
		winston.error('[maxonID] Token URL required');
	} else if (constants.scope === undefined || constants.scope === '') {
		winston.error('[maxonID] Scope required');
	} else if (constants.userRoute === undefined || constants.userRoute === '') {
		winston.error('[maxonID] User Route required');
	} else if (constants.allowedEntitlementsList === undefined || constants.allowedEntitlementsList === '') {
		winston.error('[maxonID] Allowed entitlements list required');
	} else if (constants.setFullname === undefined) {
		winston.error('[maxonID] Set fullname flag required');
	} else {
		configOk = true;
		winston.info('[maxonID] Config is OK');
	}

	// add member variable userMaxonIDIsEmpty to identify if a user is authenticated with Maxon ID
	const OAuth = { userMaxonIDIsEmpty: true };
	const oauthOptions = constants.oauth2;
	oauthOptions.callbackURL = nconf.get('url') + '/auth/' + constants.name + '/callback';
	oauthOptions.passReqToCallback = true;

	OAuth.getStrategy = function (strategies, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.getStrategy'); }

		let passportOAuth;
		if (configOk) {
			passportOAuth = require('passport-oauth2');

			passportOAuth.Strategy.prototype.userProfile = function (accessToken, done) {
				if (!accessToken) {
					done(new Error('Missing token, cannot call the userinfo endpoint without it.'));
				}
				this._oauth2.useAuthorizationHeaderforGET(true);
				this._oauth2.get(constants.userRoute, accessToken, function (err, body, res) {
					if (err) {
						console.error(err);
						return done(new Error('Failed to get user info. Exception was previously logged.'));
					}

					if (res.statusCode < 200 || res.statusCode > 299) {
						return done(new Error('Unexpected response from userInfo. [' + res.statusCode + '] [' + body + ']'));
					}

					// validate the user permissions given the current access token and the list of allowed entitlements
					OAuth.validateEntitlementsList(accessToken, constants.allowedEntitlementsList, function (err, accessAllowed) {
						if (constants.debugOutput !== undefined && constants.debugOutput) {
							winston.verbose('[maxonID] OAuth.validateEntitlementsList');
							console.log('validateEntitlementsList result:', accessAllowed);
						}

						if (err) {
							return done(err);
						}

						// if (!accessAllowed) {
						// 	// Need to find a way to gracefully notify the user and point back to login page
						// 	return done(new Error('Forum access is not granted. Please contact your Maxon representative.'));
						// }

						try {
							const parsedBody = JSON.parse(body);
							OAuth.parseUserReturn(parsedBody, function (err, profile) {
								if (err) {
									return done(err);
								}

								profile.provider = constants.name;
								profile.isPremium = accessAllowed;

								if (constants.debugOutput !== undefined && constants.debugOutput) {
									winston.verbose('[maxonID] Profile:');
									console.log(profile);
								}

								done(null, profile);
							});
						} catch (e) {
							done(e);
						}
					});
				});
			};

			passport.use(constants.name, new passportOAuth(oauthOptions, function (req, token, secret, profile, done) {
				OAuth.login({
					oAuthid: profile.id,
					handle: profile.handle,
					email: profile.emails[0].value,
					isPremium: profile.isPremium,
					name: profile.givenName,
					surname: profile.familyName,
				}, function (err, user) {
					if (err) {
						return done(err);
					}

					authenticationController.onSuccessfulLogin(req, user.uid);
					done(null, user);
				});
			}));

			strategies.push({
				name: constants.name,
				url: '/auth/' + constants.name,
				callbackURL: '/auth/' + constants.name + '/callback',
				icon: 'fa-lock',
				scope: (constants.scope || '').split(','),
			});

			callback(null, strategies);
		} else {
			callback(new Error('OAuth Configuration is invalid'));
		}
	};

	OAuth.validateEntitlementsList = function (token, entitlementsList, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.validateEntitlementsList'); }
		let completed_requests = 0; // count the number of requests completed
		let isAllowed = false; // store (sums via or) the entitlements allowance
		// loop through all the entitlements set in nodebb config.json
		for (var i = 0; i < entitlementsList.length; i += 1) {
			// prepare the input data to check if the user own the specific entitlement
			const item = [token.toString(), entitlementsList[i]];
			OAuth.checkEntitlement(item, function (response) {
				// sum the allowance
				isAllowed = isAllowed || response;
				completed_requests += 1;

				if (completed_requests === entitlementsList.length) {
					// return only all the requests have been completed
					callback(null, isAllowed);
				}
			});
		}
	};

	OAuth.checkEntitlement = function (inputData, callback) {
		const checkURL = nconf.get('oauth_plugin:idserver') + '/authz/.json?' + inputData[1] + '&doConsume=false';
		if (constants.debugOutput !== undefined && constants.debugOutput) winston.verbose('[maxonID] OAuth.checkEntitlement');
		if (useUnirestAPI) {
			const unirest = require('unirest');
			unirest('GET', checkURL)
				.headers({
					Authorization: 'Bearer ' + inputData[0],
				})
				.end(function (response) {
					if (response.error) throw new Error(response.error);

					const parsedBody = JSON.parse(response.raw_body);
					if (constants.debugOutput !== undefined && constants.debugOutput) console.log(parsedBody);
					if (typeof parsedBody[inputData[1]] !== 'undefined') {
						if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], parsedBody[inputData[1]]);
						return (callback(parsedBody[inputData[1]]));
					}
					if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], false);
					return (callback(false));
				});
		} else {
			const request = require('request');
			const requestOptions = {
				method: 'GET',
				url: checkURL,
				headers: {
					Authorization: 'Bearer ' + inputData[0],
				},
			};
			request(requestOptions, function (error, response) {
				if (error) { throw new Error(error); }

				const parsedBody = JSON.parse(response.body);
				if (constants.debugOutput !== undefined && constants.debugOutput) console.log(parsedBody);
				if (typeof parsedBody[inputData[1]] !== 'undefined') {
					if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], parsedBody[inputData[1]]);
					return (callback(parsedBody[inputData[1]]));
				}
				if (constants.debugOutput !== undefined && constants.debugOutput) console.log(inputData[1], false);
				return (callback(false));
			});
		}
	};

	OAuth.parseUserReturn = function (data, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) {
			winston.verbose('[maxonID] OAuth.parseUserReturn');
			console.log(data);
		}

		const profile = {};
		profile.id = data.sub;
		profile.givenName = data.given_name;
		profile.familyName = data.family_name;
		profile.emails = [{ value: data.email }];

		if (data.nickname === undefined || data.nickname === '') {
			if (constants.usernameStrategy === undefined || constants.usernameStrategy === 'two-words') {
				const firstWord = commonWords[Math.floor(Math.random() * (commonWords.length - 1))];
				let secondWord = commonWords[Math.floor(Math.random() * (commonWords.length - 1))];
				while (secondWord === firstWord) secondWord = commonWords[Math.floor(Math.random() * (commonWords.length - 1))];

				profile.handle = firstWord + '-' + secondWord;
			} else if (constants.usernameStrategy === 'email') {
				profile.handle = data.email.split('@')[0];
			} else if (constants.usernameStrategy === 'name_surname') {
				profile.handle = data.given_name[0].toLowerCase() + '_' + data.family_name.toLowerCase();
			}
		} else {
			profile.handle = data.nickname;
		}

		callback(null, profile);
	};

	OAuth.login = function (payload, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) {
			winston.verbose('[maxonID] OAuth.login');
			console.log(payload);
		}

		OAuth.getUidByOAuthid(payload.oAuthid, function (err, uid) {
			if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.getUidByOAuthid'); }

			if (err) { return callback(err); }

			if (uid !== null) {
				// Existing user

				// add user to premium group
				if (payload.isPremium) {
					if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] Existing user is Premium, join the group'); }
					groups.join(constants.premiumGroupId, uid, function (err) {
						callback(err, { uid: uid });
					});
				} else {
					if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] Existing user is Premium, leave the group'); }
					groups.leave(constants.premiumGroupId, uid, function (err) {
						callback(err, { uid: uid });
					});
				}
				callback(null, {
					uid: uid,
				});
			} else {
				// New user
				const success = function (uid) {
					// store oAuthID information
					user.setUserField(uid, constants.name + 'Id', payload.oAuthid);
					db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

					// check given_name and family_name to generate a proper username (aka displayName)
					if (constants.setFullname && payload.name !== undefined && payload.name !== '' && payload.surname !== undefined && payload.surname !== '') {
						// set fullname
						user.setUserField(uid, 'fullname', payload.name + ' ' + payload.surname);
						db.setObjectField('fullname', payload.name + ' ' + payload.surname, uid);
					}

					// add user to "Maxon" group if registered email address belongs to "maxon.net" domain
					const domain = payload.email.split('@')[1];
					if (domain === 'maxon.net' || domain === 'redgiant.com' || domain === 'external.team' || domain === 'maxon.de') {
						groups.join('Maxon', uid, function (err) {
							callback(err, { uid: uid });
						});
					}

					// add user to premium group
					if (payload.isPremium) {
						if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] New user is Premium, join the group'); }
						groups.join(constants.premiumGroupId, uid, function (err) {
							callback(err, { uid: uid });
						});
					}

					callback(null, { uid: uid });
				};

				user.getUidByEmail(payload.email, function (err, uid) {
					if (err) { return callback(err); }

					if (!uid) {
						user.create({
							username: payload.handle,
							email: payload.email,
						}, function (err, uid) {
							if (err) return callback(err);

							success(uid);
						});
					} else {
						success(uid); // Existing account -- merge
					}
				});
			}
		});
	};

	OAuth.getUidByOAuthid = function (oAuthid, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.getUidByOAuthid'); }
		db.getObjectField(constants.name + 'Id:uid', oAuthid, function (err, uid) {
			if (err) return callback(err);

			callback(null, uid);
		});
	};

	OAuth.deleteUserData = function (data, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.deleteUserData'); }

		async.waterfall([
			async.apply(user.getUserField, data.uid, constants.name + 'Id'),
			function (oAuthIdToDelete, next) {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			},
		], function (err) {
			if (err) {
				winston.error('[maxonID] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	OAuth.whitelistFields = function (params, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.whitelistFields'); }

		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	OAuth.redirectLogout = function (payload, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) {
			winston.verbose('[maxonID] OAuth.redirectLogout');
			console.log('userMaxonIDIsEmpty: ', OAuth.userMaxonIDIsEmpty);
		}

		if (constants.oauth2.logoutURL && !OAuth.userMaxonIDIsEmpty) {
			winston.info('[maxonID] Changing logout to Maxon ID logout');
			let separator;

			if (constants.oauth2.logoutURL.indexOf('?') === -1) { separator = '?'; } else separator = '&';

			// define the right logout redirect
			payload.next = constants.oauth2.logoutURL + separator + 'triggerSingleSignout=true';

			// reset the property to the true state
			OAuth.userMaxonIDIsEmpty = true;
		}
		return callback(null, payload);
	};

	OAuth.userLoggedOut = function (params, callback) {
		if (constants.debugOutput !== undefined && constants.debugOutput) { winston.verbose('[maxonID] OAuth.userLoggedOut'); }

		user.getUserData(params.uid, function (err, data) {
			if (err) {
				winston.error('[maxonID] Could not find data for uid ' + params.uid + '. Error: ' + err);
				return callback(err);
			}

			// set property to false to make redirectLogout to redirect only Maxon ID(s)
			if (data[constants.name + 'Id'] != null && data[constants.name + 'Id'].length !== 0) { OAuth.userMaxonIDIsEmpty = false; }

			callback(null, params);
		});
	};

	// Method responsible to check user authentication and deliver Maxon binaries based on actual location
	// Method responsible to re-route non authenticated user to landing
	OAuth.routesOnLoad = function (data, callback) {
		const app = data.app;

		// re-route non authenticated users to landing
		app.get('/', function (req, res) {
			// check the user to be logged in
			if (req.loggedIn) {
				res.redirect('/categories');
			} else res.redirect('/landing');
		});

		callback(null);
	};

	module.exports = OAuth;
}(module));
