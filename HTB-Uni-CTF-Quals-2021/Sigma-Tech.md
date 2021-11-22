# Sigma Technology

**Writeup by:** arcayn
**Category:** Misc
**Difficulty:** Medium

We are given a download and a wesbite to connect to. The challenge description asks us
> Can you use your laser pointer to change some of the robot's vision pixels forcing it to misclassify your dog's image as a non-animal object?

Visiting the website, we can see an image of a dog, and the ability to enter 5 strings. Each string corresponds to an `(x,y)` coordinate on the image, followed by an rgb value. Entering random strings, the website tells us that our dog has been identified as an animal by the robot, and then kidnapped! From this, combined with the challenge description, we can infer the following about the challenge
	- The strings we enter correspond to changing single pixel values of the `dog.png` image
	- This will then be run through a neural network-based image classifier. If the classifier returns that the image is an animal, we lose. If it classifies it as something inanimate, then we win (and presumably get the flag)
	
Now the python downloadable seems to give us access to the classifier used by the website - it is a simple wrapper around a Keras classifier, the data for which is provided in `sigmanet.h5`.

Let's download the `dog.png` image and see how it's classified.  We add the line
`print (list(zip(class_names,confidence)))`
into `predict_one` in order to see the whole output of the classifier.
```
[('airplane', 2.1547568e-09), ('automobile', 6.919757e-08), ('bird', 3.207556e-08), ('cat', 1.7548535e-05), ('deer', 5.456032e-05), ('dog', 0.9998697), ('frog', 6.305067e-06), ('horse', 5.165475e-05), ('ship', 1.4958709e-09), ('truck', 4.67897e-09)]
```
We can see that the network is very sure that it's seeing a dog. Our best chance at a non-animal object is `automobile`, which is ranked slightly higher than the others.

Our strategy now is fairly simple. We want to maximise an objective function which takes as its input 5 `(x,y,r,g,b)` strings representing pixel changes, and outputs the confidence of the neural net that `dog.png` after those 5 pixel changes is, in fact, an `automobile`. We begun researching potential methods for doing this, including using another neural net to work backwards off the initial one - however I chose to see whether the simplest solution would work first.

We will simply perform greedy optimisation:
- Start with an unmodified image
- Pick a color and try switching each pixel to that colour one by one and rank the automobile confidence of the image with that pixel switched.
- Choose the pixel which achieves the maximum confidence level, and update the image to contain that changed pixel
- Repeat from setep 2 until we have changed 5 pixels

Some initial testing showed that red pixels (`rgb(255,0,0)`) confused the network more than others (and it's the colour of a laser pointer!), so I chose to use red pixels initially.

To my surprise, we didn't need any sophisticated optimisation techniques, and this crude method was enough to find a solution. The solve script is modified from the downloadable and given by:

```python
import numpy as np
from keras.models import load_model
from keras.preprocessing import image

class_names = ['airplane', 'automobile', 'bird', 'cat', 'deer', 'dog', 'frog', 'horse', 'ship', 'truck']

class SigmaNet:
    def __init__(self):
        self.name = 'sigmanet'
        self.model_filename = 'sigmanet.h5'
        try:
            self._model = load_model(self.model_filename)
            print('Successfully loaded', self.name)
        except (ImportError, ValueError, OSError):
            print('Failed to load', self.name)

    def color_process(self, imgs):
        if imgs.ndim < 4:
            imgs = np.array([imgs])
        imgs = imgs.astype('float32')
        mean = [125.307, 122.95, 113.865]
        std = [62.9932, 62.0887, 66.7048]
        for img in imgs:
            for i in range(3):
                img[:, :, i] = (img[:, :, i] - mean[i]) / std[i]
        return imgs

    def predict(self, img):
        processed = self.color_process(img)
        return self._model.predict(processed)

    def predict_one(self, img):
        confidence = self.predict(img)[0]
        predicted_class = np.argmax(confidence)
        return class_names[predicted_class],confidence[1]

SN = SigmaNet()
dog = image.img_to_array(image.load_img("dog.png"))
print(SN.predict_one(dog))

for r in range(5):
    best = 0
    bx,by = (0,0)
    for x in range(32):
        for y in range(32):
            F = np.copy(dog[x,y])
            dog[x,y] = [255,0,0]
            V = SN.predict_one(dog)
            if V[1] > best:
                bx,by = x,y
                best = V[1]
            dog[x,y] = F
    print ("Best this round:",best)
    print ("At coords:",bx,by)
    dog[bx,by] = [255,0,0]
```
We change to red the pixels at `(14,25)`, `(17,19)`, `(18,23)`, `(21,11)` and `(19,7)`, which yielded a confidence of `0.468`. Entering this into the website gives us the flag as:

`HTB{0ne_tw0_thr33_p1xel_attack}`