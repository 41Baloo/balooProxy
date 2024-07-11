package utils

import (
	"image"
	"image/color"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

func AddLabel(img *image.RGBA, x, y int, label string, color color.RGBA) {
	point := fixed.Point26_6{X: fixed.I(x), Y: fixed.I(y)}

	d := &font.Drawer{
		Dst:  img,
		Src:  image.NewUniform(color),
		Face: basicfont.Face7x13,
		Dot:  point,
	}
	d.DrawString(label)
}

func WarpImg(src image.Image, displacement func(x, y int) (int, int)) *image.RGBA {
	bounds := src.Bounds()
	minX := bounds.Min.X
	minY := bounds.Min.Y
	maxX := bounds.Max.X
	maxY := bounds.Max.Y

	dst := image.NewRGBA(image.Rect(minX, minY, maxX, maxY))
	for x := minX; x < maxX; x++ {
		for y := minY; y < maxY; y++ {
			dx, dy := displacement(x, y)
			if dx < minX || dx > maxX || dy < minY || dy > maxY {
				continue
			}
			dst.Set(x, y, src.At(dx, dy))
		}
	}
	return dst
}

func DrawTriangle(blacklist map[[2]int]bool, src, dst *image.RGBA, x, y, size int, shift int) map[[2]int]bool {
	for i := 0; i < size; i++ {
		for j := 0; j < size-i; j++ {
			if !blacklist[[2]int{x + i, y + j}] {
				dst.Set(x+i+shift, y+j, src.At(x+i, y+j))
				src.Set(x+i, y+j, color.RGBA{0, 0, 0, 0}) // Should probably be 0, might confuse bots tho and good for debugging
				blacklist[[2]int{x + i, y + j}] = true
			}
		}
	}

	return blacklist
}
